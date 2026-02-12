# dentry-monitor

eBPF-based per-container dentry monitoring for Kubernetes nodes.

Attaches kprobes to kernel dentry functions (`d_alloc`, `d_instantiate`, `shrink_dcache_sb`) and exposes:

- **Prometheus metrics** at `/metrics` — per-cgroup dentry allocation, positive/negative counts, node-level totals, reclaim events
- **Tracing API** at `/traces` — opt-in file path capture via ring buffer

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

Enable tracing to capture dentry filenames:

```bash
# Enable
curl -X PUT http://<node>:9090/traces/config -d '{"enabled":true}'

# View events
curl http://<node>:9090/traces?limit=10

# Filter by path pattern (userspace filtering)
curl -X PUT http://<node>:9090/traces/config \
  -d '{"enabled":true,"path_patterns":[".ibd","#sql"]}'

# Disable
curl -X PUT http://<node>:9090/traces/config -d '{"enabled":false}'
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:9090` | HTTP listen address |
| `--proc` | `/proc` | Path to host /proc |
| `--cgroup` | `/sys/fs/cgroup` | Path to host cgroup filesystem |
| `--poll-interval` | `5s` | BPF map poll interval |
| `--resolve-interval` | `30s` | Cgroup→pod resolve interval |
| `--trace-buffer` | `10000` | Trace event circular buffer size |
