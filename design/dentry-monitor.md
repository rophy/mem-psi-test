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

## Scope

### In scope (v1)
- eBPF kprobes for dentry alloc/instantiate/reclaim
- Per-cgroup counters in BPF map
- Cgroup ID → pod name resolution
- Prometheus metrics endpoint
- DaemonSet deployment manifest

### Out of scope (future)
- Grafana dashboard JSON
- AlertManager rules
- Automatic remediation (drop_caches, pod eviction)
- CRD-based configuration
- Non-K8s environments
