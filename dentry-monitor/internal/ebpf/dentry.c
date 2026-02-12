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

/* Trace event emitted to ring buffer */
struct dentry_trace_event {
    __u64 timestamp;
    __u64 cgroup_id;
    __u32 operation; /* 0=alloc, 1=positive, 2=negative */
    __u32 path_len;
    char  path[256];
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
    __uint(max_entries, 1 << 20); /* 1 MiB ring buffer */
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
 * d_alloc tracing — capture parent dentry filename.
 * This is a separate kprobe so the metrics path stays simple.
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

    /* Read the parent dentry name — this is the directory containing
     * the new dentry. Sufficient to identify patterns like /tmp, #sql, etc. */
    const unsigned char *name = BPF_CORE_READ(parent, d_name.name);
    if (name) {
        int ret = bpf_probe_read_kernel_str(evt->path, sizeof(evt->path),
                                            (void *)name);
        evt->path_len = ret > 0 ? ret - 1 : 0;
    } else {
        evt->path[0] = '\0';
        evt->path_len = 0;
    }

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
