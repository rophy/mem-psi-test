# Plan: Reproduce Node-Not-Ready via Dentry/Slab Pressure

## Context

Corporate K8s nodes experience `node-not-ready` events caused by CPU soft lockups. The suspected root cause is excessive dentry/inode slab cache growth from containers, followed by memory pressure triggering `shrink_dcache_sb()` which holds kernel spinlocks for too long, starving the kubelet.

We have a minikube cluster (KVM, 2 CPUs, 4 GiB RAM, kernel 5.10.207) to reproduce this. The kernel lacks `SOFTLOCKUP_DETECTOR`, so we focus on triggering the actual node-not-ready condition rather than the kernel message.

## Target Environment

- **Context**: `minikube`
- **Node**: 2 CPUs, 4 GiB RAM, no swap, kernel 5.10.207
- **Runtime**: Docker 28.0.4
- **Baseline slab**: ~84 MiB, ~40k dentries, ~21k inodes

## Plan

### 1. Create project structure

```
mem-psi-test/
├── namespace.yaml              # dedicated namespace
├── dentry-flooder/
│   ├── Dockerfile              # minimal image with the flood script
│   └── flood.sh                # creates millions of files (dentries)
├── memory-pressure/
│   ├── Dockerfile              # image for memory pressure tool
│   └── pressure.sh             # allocates memory to trigger reclaim
├── deploy-flood.yaml           # DaemonSet/Deployment for dentry flooding pods
├── deploy-pressure.yaml        # Job to trigger memory pressure
├── monitor.sh                  # Host-side script to watch node status + slab
└── run-test.sh                 # Orchestrates the full test sequence
```

### 2. Dentry Flooder (`dentry-flooder/flood.sh`)

- Runs inside a privileged pod
- Creates files across multiple directories to inflate dentry/inode slab caches
- Target: 2-3 million dentries (from baseline ~40k)
- Uses tmpfs and overlayfs writes to maximize dentry creation
- Runs as multiple parallel processes to fill caches faster

### 3. Memory Pressure Trigger (`memory-pressure/pressure.sh`)

- Runs as a separate pod/job after dentry flooding
- Allocates memory aggressively to push the system into reclaim
- Uses a cgroup memory limit (e.g. 3 GiB) so pressure forces kernel slab shrinking
- The goal: force `shrink_dcache_sb()` to reclaim millions of dentries under spinlock

### 4. Monitoring Script (`monitor.sh`)

Runs on the host (outside minikube), polling:
- `kubectl get nodes` — watch for NotReady transition
- `minikube ssh -- sudo slabtop -o` — watch slab cache sizes
- `minikube ssh -- cat /proc/meminfo` — watch MemAvailable/Slab
- Timestamps all observations for correlation

### 5. Test Orchestrator (`run-test.sh`)

Sequence:
1. Build and load images into minikube (`minikube image build`)
2. Apply namespace
3. Deploy dentry flooder pods (multiple replicas)
4. Wait for flooding to complete (watch slab growth)
5. Deploy memory pressure job
6. Monitor for node-not-ready event
7. Collect diagnostics (dmesg, slabinfo, node events)
8. Cleanup

### 6. Tunable Parameters

To increase likelihood of triggering the condition:
- `vm.vfs_cache_pressure=10` (lower = kernel holds more dentries, harder reclaim)
- Number of flooder pods / files per pod
- Memory pressure pod limit (how much to allocate)
- These will be configurable via environment variables in the scripts

## Verification

1. **Slab growth**: Confirm dentry/inode slab caches grow to hundreds of MiB (from baseline ~84 MiB)
2. **Reclaim trigger**: Confirm memory pressure forces slab shrinking (watch `/proc/meminfo` Slab field drop)
3. **Node impact**: Observe node transitioning to `NotReady` or kubelet heartbeat delays in node events
4. **Diagnostics**: Collect `dmesg` output showing time spent in reclaim, and `kubectl describe node` showing condition changes

## Key Risks & Mitigations

- **Test may not trigger NotReady**: 2 CPUs + 4 GiB may not produce enough contention. Mitigation: tune parameters (more files, lower vfs_cache_pressure, more pressure pods)
- **Control plane runs on same node**: Minikube is single-node, so stressing it may kill the API server too. Mitigation: monitor.sh runs from host and uses `minikube ssh` as fallback
- **Image builds**: Keep images minimal (alpine/busybox based) to avoid bloating the VM

