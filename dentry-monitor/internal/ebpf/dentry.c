//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Per-cgroup dentry statistics */
struct dentry_stats {
    __u64 alloc;
    __u64 positive;
    __u64 negative;
};

/* Trace event emitted to ring buffer.
 * Path is stored as up to 8 separate name components (leaf to root).
 * Userspace reconstructs the full path by reversing the order.
 * Bit 31 of depth is set if the walk reached the filesystem root. */
#define MAX_PATH_DEPTH 8
#define MAX_NAME_LEN 64
#define DEPTH_ROOT_FLAG 0x80000000U

struct dentry_trace_event {
    __u64 timestamp;
    __u64 cgroup_id;
    __u32 operation; /* 0=alloc, 1=positive, 2=negative */
    __u32 depth;     /* bits 0-30: component count, bit 31: reached root */
    char  names[MAX_PATH_DEPTH][MAX_NAME_LEN]; /* 8 * 64 = 512 bytes */
};

/* Tracing enabled flag (index 0 in array map) */
struct trace_config {
    __u32 enabled; /* 0=off, 1=on */
    __u32 _pad;
};

/* --- Maps --- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct dentry_stats);
} dentry_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); /* 2 MiB ring buffer */
} trace_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct trace_config);
} trace_config_map SEC(".maps");

/* Node-level reclaim counter (single-element array) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} reclaim_count SEC(".maps");

/* --- Helpers --- */

static __always_inline struct dentry_stats *get_or_create_stats(__u64 cgid) {
    struct dentry_stats *stats = bpf_map_lookup_elem(&dentry_stats_map, &cgid);
    if (stats)
        return stats;

    /* Field-by-field init to satisfy kernel 5.10 verifier */
    struct dentry_stats zero;
    zero.alloc = 0;
    zero.positive = 0;
    zero.negative = 0;
    bpf_map_update_elem(&dentry_stats_map, &cgid, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&dentry_stats_map, &cgid);
}

static __always_inline bool tracing_enabled(void) {
    __u32 key = 0;
    struct trace_config *cfg = bpf_map_lookup_elem(&trace_config_map, &key);
    return cfg && cfg->enabled;
}

/* --- Kprobes --- */

/*
 * d_alloc(struct dentry *parent, const struct qstr *name)
 *
 * Count dentry allocations per cgroup.
 */
SEC("kprobe/d_alloc")
int trace_d_alloc(struct pt_regs *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();

    struct dentry_stats *stats = get_or_create_stats(cgid);
    if (stats)
        __sync_fetch_and_add(&stats->alloc, 1);

    return 0;
}

/*
 * d_alloc tracing — capture full path (up to 8 components).
 * This is a separate kprobe so the metrics path stays simple.
 *
 * d_alloc(struct dentry *parent, const struct qstr *name)
 * - names[0] = new dentry name (from qstr PARM2)
 * - names[1..7] = ancestor directory names (parent to great^6-grandparent)
 *
 * Manually unrolled to avoid verifier issues on kernel 5.10.
 * Uses goto for early exit when root is reached (d_parent == self).
 * Sets DEPTH_ROOT_FLAG when the full path to root was captured.
 */
SEC("kprobe/d_alloc")
int trace_d_alloc_path(struct pt_regs *ctx) {
    if (!tracing_enabled())
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct dentry *parent = (struct dentry *)PT_REGS_PARM1(ctx);
    if (!parent)
        return 0;

    struct dentry_trace_event *evt = bpf_ringbuf_reserve(&trace_events,
                                          sizeof(struct dentry_trace_event), 0);
    if (!evt)
        return 0;

    evt->timestamp = bpf_ktime_get_ns();
    evt->cgroup_id = cgid;
    evt->operation = 0; /* alloc */
    evt->depth = 0;

    /* Declare all dentry pointers upfront (goto-safe) */
    const unsigned char *np;
    struct dentry *d2, *d3, *d4, *d5, *d6, *d7, *d8;

    /* names[0]: new dentry name from qstr parameter */
    const struct qstr *qname = (const struct qstr *)PT_REGS_PARM2(ctx);
    if (qname) {
        np = BPF_CORE_READ(qname, name);
        if (np) {
            bpf_probe_read_kernel_str(evt->names[0], MAX_NAME_LEN, (void *)np);
            evt->depth = 1;
        }
    }

    /* names[1]: parent */
    np = BPF_CORE_READ(parent, d_name.name);
    if (np) {
        bpf_probe_read_kernel_str(evt->names[1], MAX_NAME_LEN, (void *)np);
        if (evt->depth < 2) evt->depth = 2;
    }

    /* names[2] */
    d2 = BPF_CORE_READ(parent, d_parent);
    if (!d2 || d2 == parent) goto reached_root;
    np = BPF_CORE_READ(d2, d_name.name);
    if (np) { bpf_probe_read_kernel_str(evt->names[2], MAX_NAME_LEN, (void *)np); evt->depth = 3; }

    /* names[3] */
    d3 = BPF_CORE_READ(d2, d_parent);
    if (!d3 || d3 == d2) goto reached_root;
    np = BPF_CORE_READ(d3, d_name.name);
    if (np) { bpf_probe_read_kernel_str(evt->names[3], MAX_NAME_LEN, (void *)np); evt->depth = 4; }

    /* names[4] */
    d4 = BPF_CORE_READ(d3, d_parent);
    if (!d4 || d4 == d3) goto reached_root;
    np = BPF_CORE_READ(d4, d_name.name);
    if (np) { bpf_probe_read_kernel_str(evt->names[4], MAX_NAME_LEN, (void *)np); evt->depth = 5; }

    /* names[5] */
    d5 = BPF_CORE_READ(d4, d_parent);
    if (!d5 || d5 == d4) goto reached_root;
    np = BPF_CORE_READ(d5, d_name.name);
    if (np) { bpf_probe_read_kernel_str(evt->names[5], MAX_NAME_LEN, (void *)np); evt->depth = 6; }

    /* names[6] */
    d6 = BPF_CORE_READ(d5, d_parent);
    if (!d6 || d6 == d5) goto reached_root;
    np = BPF_CORE_READ(d6, d_name.name);
    if (np) { bpf_probe_read_kernel_str(evt->names[6], MAX_NAME_LEN, (void *)np); evt->depth = 7; }

    /* names[7] */
    d7 = BPF_CORE_READ(d6, d_parent);
    if (!d7 || d7 == d6) goto reached_root;
    np = BPF_CORE_READ(d7, d_name.name);
    if (np) { bpf_probe_read_kernel_str(evt->names[7], MAX_NAME_LEN, (void *)np); evt->depth = 8; }

    /* Check if there are more levels beyond 8 */
    d8 = BPF_CORE_READ(d7, d_parent);
    if (!d8 || d8 == d7) goto reached_root;

    /* Truncated — more levels exist but we capped at 8 */
    goto submit;

reached_root:
    evt->depth |= DEPTH_ROOT_FLAG;

submit:
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/*
 * d_instantiate(struct dentry *dentry, struct inode *inode)
 *
 * Classify dentry as positive (inode != NULL) or negative (inode == NULL).
 */
SEC("kprobe/d_instantiate")
int trace_d_instantiate(struct pt_regs *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct inode *inode = (struct inode *)PT_REGS_PARM2(ctx);

    struct dentry_stats *stats = get_or_create_stats(cgid);
    if (!stats)
        return 0;

    if (inode) {
        __sync_fetch_and_add(&stats->positive, 1);
    } else {
        __sync_fetch_and_add(&stats->negative, 1);
    }

    return 0;
}

/*
 * shrink_dcache_sb(struct super_block *sb)
 *
 * Count reclaim events. Low frequency.
 */
SEC("kprobe/shrink_dcache_sb")
int trace_shrink_dcache(struct pt_regs *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&reclaim_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}
