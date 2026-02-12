# Design: eBPF-based Dentry Monitor

## Problem

Kubernetes nodes with large memory (768 GiB+) running MariaDB workloads
accumulate billions of dentry objects in the kernel cache. When memory pressure
triggers reclaim, the kernel holds a spinlock while walking the entire dentry
list — causing CPU soft lockups and node-not-ready events.

Today there is no visibility into:
- Which containers are creating the most dentries
- Whether dentries are accumulating faster than they're being reclaimed
- How close a node is to the danger threshold (~55M+ dentries)

## Goal

Provide **per-container dentry monitoring** on Kubernetes nodes so that
operators can:

1. **Identify top contributors** — see which pods/containers generate the most
   dentry operations, enabling targeted remediation (tune MariaDB, adjust
   `innodb_file_per_table`, reduce temp table churn)

2. **Detect accumulation early** — monitor node-level dentry count over time
   and alert before it reaches dangerous levels, instead of discovering the
   problem via node-not-ready events

3. **Observe reclaim events** — know when the kernel is actively reclaiming
   dentries, which correlates with CPU stalls and latency spikes

## What Users Get

### Prometheus Metrics

A `/metrics` endpoint on each node exposes:

```
# Which containers are creating dentries and how fast
dentry_alloc_total{pod="mariadb-0", namespace="production", container="mariadb"} 48291037

# Positive vs negative dentry breakdown per container
dentry_positive_total{pod="mariadb-0", ...} 40000000
dentry_negative_total{pod="mariadb-0", ...} 8291037

# Node-level totals (from /proc/sys/fs/dentry-state)
node_dentry_count{type="total"} 1526564907
node_dentry_count{type="unused"} 1500000000
node_dentry_count{type="negative"} 1400000000

# Reclaim events (kernel shrink_dcache_sb calls)
node_dentry_reclaim_total 42
```

### Grafana Dashboards (future)

- Per-pod dentry allocation rate (dentries/sec)
- Node dentry count over time with threshold line
- Top 10 pods by dentry creation rate
- Reclaim events correlated with CPU utilization

### Alerting (future)

- Alert when node dentry count exceeds threshold (e.g. 50M)
- Alert when per-pod dentry rate exceeds baseline
- Alert when reclaim events spike

## Architecture

```
┌─────────────────────────────────────────────┐
│  DaemonSet Pod (one per node)               │
│                                             │
│  ┌──────────┐    ┌───────────────────────┐  │
│  │ eBPF     │    │ Go userspace          │  │
│  │ kprobes  │───>│  - poll BPF maps      │  │
│  │ (kernel) │    │  - cgroup → pod name  │  │
│  └──────────┘    │  - serve /metrics     │  │
│                  └───────────────────────┘  │
└─────────────────────────────────────────────┘
         │
         ▼
   Prometheus scrape :9090/metrics
```

**eBPF kprobes** attach to kernel dentry functions and increment per-cgroup
counters in a BPF hash map. The Go userspace process polls the map every few
seconds, resolves cgroup IDs to pod names via the Kubernetes API, and exposes
the results as Prometheus metrics.

### Why eBPF

- **Zero overhead on hot path**: counters are incremented in kernel space;
  no per-event context switch to userspace
- **Per-container granularity**: `bpf_get_current_cgroup_id()` identifies
  which container triggered each dentry operation
- **No kernel modification**: kprobes attach dynamically, no custom kernel
  build required

### Kernel Hooks

| Hook | Function | Frequency | Purpose |
|------|----------|-----------|---------|
| kprobe | `d_alloc` | High | Count dentry allocations per cgroup |
| kprobe | `d_instantiate` | High | Classify as positive or negative |
| kprobe | `shrink_dcache_sb` | Low | Count reclaim events |

## Technology Choices

- **Language**: Go (cilium/ebpf for eBPF, client-go for K8s, prometheus/client_golang)
- **eBPF map**: `BPF_MAP_TYPE_HASH` keyed by cgroup ID — userspace polls, no ring buffer needed
- **Container**: multi-stage Docker build (golang + clang → distroless)
- **Deployment**: DaemonSet with privileged access for kprobe attachment

## Tracing Mode

Metrics show **which containers** create the most dentries, but not **which files**.
To understand exactly how MariaDB generates dentries (e.g. temp table patterns,
`.ibd` file churn), tracing mode captures individual file paths.

### How It Works

```
┌──────────────────────────────────────────────────────┐
│  Kernel (eBPF)                                       │
│                                                      │
│  kprobe/d_alloc:                                     │
│    1. Read filename from dentry->d_name.name         │
│    2. Walk d_parent chain to build path (up to 8     │
│       levels)                                        │
│    3. Check path against filter (e.g. ".ibd", "#sql",│
│       "/tmp")                                        │
│    4. If match → emit event to BPF ring buffer       │
│       {timestamp, cgroup_id, operation, path}        │
└──────────────┬───────────────────────────────────────┘
               │ BPF_MAP_TYPE_RINGBUF
               ▼
┌──────────────────────────────────────────────────────┐
│  Userspace (Go)                                      │
│                                                      │
│    - Consume ring buffer events                      │
│    - Resolve cgroup_id → pod/namespace/container     │
│    - Store in circular buffer (last N events)        │
│    - Expose via HTTP API                             │
└──────────────────────────────────────────────────────┘
```

### Why Ring Buffer

Unlike the metrics path (hash map, polled), tracing needs to export
variable-length file paths per event. `BPF_MAP_TYPE_RINGBUF` supports:
- Variable-size records (paths vary from 10 to 200+ bytes)
- Lock-free, multi-producer writes from eBPF programs
- Efficient epoll-based consumption in userspace

### Kernel-side Filtering

At millions of dentry ops/sec, emitting every event would overwhelm the ring
buffer and userspace. The eBPF program filters in-kernel:

- **Path pattern matching**: only emit events where the filename contains
  configurable substrings (e.g. `.ibd`, `#sql`, `/tmp`, `.frm`)
- **Rate limiting**: per-cgroup token bucket, e.g. max 100 events/sec per
  container
- **Cgroup filter**: optionally trace only specific cgroup IDs

Filters are configured via a BPF array map that userspace populates at startup
and can update at runtime via the HTTP API.

### eBPF Path Reconstruction

```c
// Walk up to 8 levels of d_parent to reconstruct path
SEC("kprobe/d_alloc")
int trace_d_alloc_path(struct pt_regs *ctx) {
    struct dentry *parent = (struct dentry *)PT_REGS_PARM1(ctx);
    char path[256] = {};
    int pos = 255;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        struct qstr name;
        bpf_probe_read_kernel(&name, sizeof(name), &parent->d_name);
        char component[32];
        int len = bpf_probe_read_kernel_str(component, sizeof(component),
                                            (void *)name.name);
        if (len <= 1) break;
        // prepend /component to path buffer
        pos -= len;
        if (pos < 0) break;
        path[pos] = '/';
        bpf_probe_read_kernel(&path[pos+1], len, component);
        // walk up
        bpf_probe_read_kernel(&parent, sizeof(parent), &parent->d_parent);
    }
    // ... apply filter, emit to ring buffer if matched
}
```

### HTTP API

Tracing results are exposed via a JSON HTTP API on the same port as metrics:

**`GET /traces`** — returns recent dentry trace events

```json
{
  "events": [
    {
      "timestamp": "2024-01-15T10:30:45.123Z",
      "pod": "mariadb-0",
      "namespace": "production",
      "container": "mariadb",
      "operation": "alloc",
      "path": "/var/lib/mysql/tmp/#sql_1234_0.ibd"
    },
    {
      "timestamp": "2024-01-15T10:30:45.124Z",
      "pod": "mariadb-0",
      "namespace": "production",
      "container": "mariadb",
      "operation": "alloc",
      "path": "/var/lib/mysql/tmp/#sql_1234_1.frm"
    }
  ],
  "total": 2,
  "buffer_size": 10000,
  "dropped": 0
}
```

Query parameters:
- `?pod=mariadb-0` — filter by pod name
- `?namespace=production` — filter by namespace
- `?path=.ibd` — filter by path substring
- `?limit=100` — max events to return (default 100)
- `?since=2024-01-15T10:30:00Z` — events after timestamp

**`GET /traces/config`** — view current trace filter configuration

**`PUT /traces/config`** — update trace filters at runtime

```json
{
  "enabled": true,
  "path_patterns": [".ibd", "#sql", ".frm", "/tmp"],
  "rate_limit_per_cgroup": 100,
  "cgroup_filter": []
}
```

### Tracing vs Metrics

| Aspect | Metrics mode | Tracing mode |
|--------|-------------|--------------|
| Data | Counters per cgroup | Individual file paths |
| Overhead | Near zero | Low (filtered) |
| Always on | Yes | Opt-in |
| Storage | BPF hash map | BPF ring buffer → circular buffer |
| Export | Prometheus `/metrics` | HTTP `/traces` |
| Use case | Monitoring & alerting | Root cause investigation |

Tracing is designed for **investigation sessions** — enable it when you need
to understand what a specific container is doing, then disable it. Metrics
mode runs continuously for monitoring and alerting.

## Scope

### In scope (v1)
- eBPF kprobes for dentry alloc/instantiate/reclaim
- Per-cgroup counters in BPF map
- Cgroup ID → pod name resolution
- Prometheus metrics endpoint
- Tracing mode with path capture and HTTP API
- DaemonSet deployment manifest

### Out of scope (future)
- Grafana dashboard JSON
- AlertManager rules
- Automatic remediation (drop_caches, pod eviction)
- CRD-based configuration
- Non-K8s environments
