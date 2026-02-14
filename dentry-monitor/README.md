# dentry-monitor

eBPF-based per-container dentry monitoring for Kubernetes nodes.

Attaches kprobes to kernel dentry functions (`d_alloc`, `d_instantiate`, `shrink_dcache_sb`) and exposes:

- **Prometheus metrics** at `/metrics` — per-cgroup dentry allocation, positive/negative counts, node-level totals, reclaim events
- **Trace file output** — opt-in file path capture written to TSV files with size-based rotation

## Build

```bash
docker build -t dentry-monitor:local .
```

Requires Docker only. The multi-stage build compiles eBPF C with clang and Go with golang:1.24.

## Deploy

```bash
kubectl apply -f deploy/daemonset.yaml
```

The DaemonSet runs one pod per node with privileged access for kprobe attachment.
Trace files are written to the host at `/var/log/dentry-monitor/`.

## Usage

### Metrics

```bash
curl http://<node>:9090/metrics
```

Key metrics:
- `dentry_alloc_total{pod, namespace, container}` — dentry allocations per container
- `dentry_positive_total` / `dentry_negative_total` — positive vs negative dentries
- `dentry_count{type="total|unused|negative"}` — node-level from `/proc/sys/fs/dentry-state`
- `dentry_reclaim_total` — kernel reclaim events

### Tracing

Tracing is controlled via CLI flags. When enabled, dentry path events are written to TSV files.

```bash
# Enable tracing at startup
dentry-monitor --trace-enabled --trace-dir=/data/traces

# Filter to specific path patterns
dentry-monitor --trace-enabled --trace-patterns=".ibd,#sql,.frm"
```

#### Output files

Files are written to `--trace-dir` with size-based rotation:

```
/var/log/dentry-monitor/
├── traces.tsv       # active file
├── traces.tsv.1     # most recent rotated
├── traces.tsv.2
└── traces.tsv.3     # oldest
```

#### File format

Tab-separated values with header:

```
timestamp	pod	container	cgroup_id	operation	path	fstype
```

Example lines:

```
2026-02-13T18:54:13.648795455Z			3788	alloc	/var/lib/minikube/etcd/member/snap/0000000000000003.snap	ext4
2026-02-13T19:09:00.768833899Z			3080	alloc	system.slice/kubelet.service/memory.swap.peak	cgroup2
2026-02-13T18:43:23.513499951Z			2890	alloc	/usr/local/sbin/runc	tmpfs
```

#### Querying

```bash
# View latest events
tail -f /var/log/dentry-monitor/traces.tsv

# Filter to ext4 events
grep ext4 /var/log/dentry-monitor/traces.tsv

# Count events by filesystem type
awk -F'\t' 'NR>1 {fs[$7]++} END {for(f in fs) print f, fs[f]}' traces.tsv
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:9090` | HTTP listen address |
| `--proc` | `/proc` | Path to host /proc |
| `--cgroup` | `/sys/fs/cgroup` | Path to host cgroup filesystem |
| `--poll-interval` | `5s` | BPF map poll interval |
| `--resolve-interval` | `30s` | Cgroup→pod resolve interval |
| `--trace-enabled` | `false` | Enable dentry path tracing on startup |
| `--trace-dir` | `/data/traces` | Directory for trace TSV output files |
| `--trace-max-size` | `100` | Max trace file size in MB before rotation |
| `--trace-max-files` | `3` | Number of rotated trace files to keep |
| `--trace-patterns` | (empty) | Comma-separated path substring filters |
