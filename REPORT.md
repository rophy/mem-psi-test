# Dentry Reclaim Benchmark Report

## Background

Corporate Kubernetes nodes (768 GiB RAM) running MariaDB workloads experience
periodic `node-not-ready` events caused by CPU soft lockups. Investigation
revealed **1,526,564,907 dentry objects** (~272 GiB of slab cache) on affected
nodes.

The suspected root cause: when memory pressure triggers dentry reclaim, the
kernel function `shrink_dcache_for_umount()` walks the entire dentry list under
a spinlock. With billions of entries, this holds the CPU for minutes — far
exceeding the 20-second soft lockup threshold.

This benchmark quantifies the reclaim cost per dentry to validate that theory.

## Method

1. Mount a tmpfs filesystem inside a minikube VM (kernel 5.10.207, 2 CPUs, 4 GiB RAM)
2. Create N hard links using a compiled C tool (`dentry-creator.c`) at ~430k links/sec
3. Measure kernel dentry count before and after unmount via `/proc/slabinfo`
4. Time the `umount()` call — this invokes `shrink_dcache_for_umount()`, the same
   kernel code path triggered during container destruction
5. Calculate ns/dentry and extrapolate to 1.5 billion dentries

Hard links are used because they share a single inode, costing only ~192 bytes
per dentry (vs ~900 bytes for individual files), allowing more dentries per byte
of available RAM.

## Test Environment

| Parameter | Value |
|---|---|
| VM | minikube (KVM driver) |
| Kernel | 5.10.207 (Buildroot) |
| CPUs | 2 |
| RAM | 4 GiB |
| Filesystem | tmpfs (nr_inodes=0) |
| Tool | dentry-creator.c (static binary, direct link() syscalls) |

## Results

| Target | Dentries Reclaimed | Unmount Time | ns/dentry | Extrapolated to 1.5B |
|---|---|---|---|---|
| 100k | 99,600 | 43 ms | 433 ns | 649 s |
| 500k | 499,948 | 211 ms | 423 ns | 634 s |
| 1M | 999,917 | 365 ms | 365 ns | 547 s |
| 2M | 1,999,782 | 758 ms | 379 ns | 568 s |
| 5M | 4,999,470 | 1,818 ms | 363 ns | 544 s |
| 10M | 9,999,922 | 3,686 ms | 368 ns | 552 s |

## Analysis

### Reclaim cost is linear (O(n))

The per-dentry cost is remarkably consistent at **363–433 ns/dentry** across two
orders of magnitude (100k to 10M). This confirms `shrink_dcache_for_umount()`
performs a linear walk — it must visit every dentry in the superblock's list.

### Soft lockup threshold math

The kernel soft lockup detector fires when a CPU is stuck in kernel mode for
**20 seconds** (2 × `kernel.watchdog_thresh`, default 10s).

At 368 ns/dentry (median from 1M+ tests):

| Dentry Count | Reclaim Time | Exceeds 20s? |
|---|---|---|
| 10 million | 3.7 s | No |
| 55 million | 20.2 s | **Threshold** |
| 100 million | 36.8 s | Yes (1.8x) |
| 500 million | 184 s | Yes (9.2x) |
| **1.5 billion** | **552 s (~9.2 min)** | **Yes (27.6x)** |

Only **~55 million dentries** are needed to trigger a soft lockup. The production
nodes have **27x that amount**.

### Production would be worse

This benchmark represents a **best case**:

- **No NUMA**: The test VM is UMA. Production 768 GiB nodes have multi-socket
  NUMA topology. Cross-node memory access adds latency to every dentry walk step.
- **No contention**: The benchmark runs on an idle system. Production nodes have
  hundreds of containers with concurrent filesystem operations contending on the
  same spinlock.
- **No other reclaim**: The benchmark only exercises the unmount path. In
  production, `shrink_dcache_sb()` (called during memory pressure) has additional
  overhead from LRU list management and reference counting.
- **Warm caches**: The test dentries were just created and are hot in CPU cache.
  Production dentry lists span hundreds of GiB, causing constant cache misses.

A realistic multiplier for production is 2–5x, putting the actual reclaim time
at **18–46 minutes** for 1.5B dentries.

## Root Cause

MariaDB containers are the primary source of dentry accumulation:

1. **InnoDB file-per-table** (`innodb_file_per_table=ON`, default since 5.6):
   each table/partition gets its own `.ibd` file, creating a dentry
2. **Temporary tables**: `CREATE TEMPORARY TABLE` / `DROP TEMPORARY TABLE` cycles
   create and destroy files, but negative dentries (cache entries for deleted
   paths) persist indefinitely on large-memory systems
3. **INFORMATION_SCHEMA queries**: scanning metadata opens every table file,
   inflating the positive dentry cache
4. **768 GiB RAM**: the kernel's default `vfs_cache_pressure=100` is too low for
   this memory size — the system never feels enough pressure to reclaim dentries
   proactively

## Recommendations

### Short-term mitigations

1. **Increase `vfs_cache_pressure`** to 200–500 on affected nodes:
   ```
   sysctl -w vm.vfs_cache_pressure=500
   ```
   This makes the kernel more aggressive about reclaiming dentries before they
   accumulate to dangerous levels.

2. **Periodic manual reclaim** via cron (with caution):
   ```
   echo 2 > /proc/sys/vm/drop_caches
   ```
   Only effective when dentry count is still moderate. Running this when count
   is already in the billions could itself trigger the soft lockup.

3. **Monitor dentry count** as a node-level metric:
   ```
   awk '/^dentry/{print $2}' /proc/slabinfo
   ```
   Alert when count exceeds 50 million (approaching the 20s threshold).

### Long-term fixes

4. **Kernel upgrade**: newer kernels (5.15+) have patches to break up large
   dentry walks with `cond_resched()` calls, preventing single-CPU monopolization.

5. **Limit MariaDB temp table churn**: tune `tmp_table_size` and `max_heap_table_size`
   to keep temporary tables in memory rather than on disk.

6. **Review INFORMATION_SCHEMA usage**: audit queries that scan all tables,
   especially from monitoring tools or ORMs.

## Reproducing

```bash
# Prerequisites: minikube running with KVM driver
minikube start --driver=kvm2 --memory=4096 --cpus=2

# Run the benchmark
./benchmark-reclaim.sh
```

The benchmark auto-compiles `dentry-creator.c` and copies it to the VM.

## References

- [Red Hat Bug #1471875](https://bugzilla.redhat.com/show_bug.cgi?id=1471875) — soft lockups during unmount with large dentry cache
- [moby/moby #12481](https://github.com/moby/moby/issues/12481) — CPU soft lockup with containers
- [LWN: Limiting negative dentries](https://lwn.net/Articles/813363/) — kernel patch to cap negative dentry accumulation
- Linux kernel source: `fs/dcache.c` → `shrink_dcache_for_umount()`
