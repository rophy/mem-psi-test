package metrics

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rophy/mem-psi-test/dentry-monitor/internal/cgroupmap"
)

// DentryStats matches the eBPF struct dentry_stats.
type DentryStats struct {
	Alloc    uint64
	Positive uint64
	Negative uint64
}

// Collector polls BPF maps and exposes Prometheus metrics.
type Collector struct {
	statsMap    *ebpf.Map
	reclaimMap  *ebpf.Map
	resolver    *cgroupmap.Resolver
	procRoot    string

	// Prometheus descriptors
	allocDesc   *prometheus.Desc
	posDesc     *prometheus.Desc
	negDesc     *prometheus.Desc
	reclaimDesc *prometheus.Desc
	nodeDesc    *prometheus.Desc

	mu    sync.Mutex
	stats map[uint64]DentryStats // snapshot from last poll
}

// NewCollector creates a metrics collector.
func NewCollector(statsMap, reclaimMap *ebpf.Map, resolver *cgroupmap.Resolver, procRoot string) *Collector {
	return &Collector{
		statsMap:   statsMap,
		reclaimMap: reclaimMap,
		resolver:   resolver,
		procRoot:   procRoot,
		stats:      make(map[uint64]DentryStats),
		allocDesc: prometheus.NewDesc(
			"dentry_alloc_total",
			"Total dentry allocations per container",
			[]string{"pod", "container"}, nil,
		),
		posDesc: prometheus.NewDesc(
			"dentry_positive_total",
			"Total positive dentry instantiations per container",
			[]string{"pod", "container"}, nil,
		),
		negDesc: prometheus.NewDesc(
			"dentry_negative_total",
			"Total negative dentry instantiations per container",
			[]string{"pod", "container"}, nil,
		),
		reclaimDesc: prometheus.NewDesc(
			"dentry_reclaim_total",
			"Total dentry reclaim events (shrink_dcache_sb calls)",
			nil, nil,
		),
		nodeDesc: prometheus.NewDesc(
			"dentry_count",
			"Node-level dentry counts from /proc/sys/fs/dentry-state",
			[]string{"type"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.allocDesc
	ch <- c.posDesc
	ch <- c.negDesc
	ch <- c.reclaimDesc
	ch <- c.nodeDesc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	snapshot := c.stats
	c.mu.Unlock()

	for cgID, s := range snapshot {
		pod, ctr := c.resolveLabels(cgID)
		ch <- prometheus.MustNewConstMetric(c.allocDesc, prometheus.CounterValue,
			float64(s.Alloc), pod, ctr)
		ch <- prometheus.MustNewConstMetric(c.posDesc, prometheus.CounterValue,
			float64(s.Positive), pod, ctr)
		ch <- prometheus.MustNewConstMetric(c.negDesc, prometheus.CounterValue,
			float64(s.Negative), pod, ctr)
	}

	// Reclaim counter
	var reclaimKey uint32
	var reclaimVal uint64
	if err := c.reclaimMap.Lookup(&reclaimKey, &reclaimVal); err == nil {
		ch <- prometheus.MustNewConstMetric(c.reclaimDesc, prometheus.CounterValue,
			float64(reclaimVal))
	}

	// Node-level dentry state
	total, unused, negative := readDentryState(c.procRoot)
	if total >= 0 {
		ch <- prometheus.MustNewConstMetric(c.nodeDesc, prometheus.GaugeValue,
			float64(total), "total")
		ch <- prometheus.MustNewConstMetric(c.nodeDesc, prometheus.GaugeValue,
			float64(unused), "unused")
		ch <- prometheus.MustNewConstMetric(c.nodeDesc, prometheus.GaugeValue,
			float64(negative), "negative")
	}
}

// Poll reads BPF maps and updates the internal snapshot.
func (c *Collector) Poll() {
	newStats := make(map[uint64]DentryStats)

	var key uint64
	var val DentryStats
	iter := c.statsMap.Iterate()
	for iter.Next(&key, &val) {
		newStats[key] = val
	}
	if err := iter.Err(); err != nil {
		log.Printf("collector: map iterate error: %v", err)
	}

	c.mu.Lock()
	c.stats = newStats
	c.mu.Unlock()
}

// Start begins periodic polling. Call via goroutine.
func (c *Collector) Start(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	c.Poll() // initial poll
	for {
		select {
		case <-ticker.C:
			c.Poll()
		case <-stopCh:
			return
		}
	}
}

func (c *Collector) resolveLabels(cgID uint64) (pod, container string) {
	info := c.resolver.Resolve(cgID)
	if info != nil {
		return info.Pod, info.Container
	}
	return fmt.Sprintf("cgroup-%d", cgID), ""
}

// readDentryState parses /proc/sys/fs/dentry-state.
// Format: nr_dentry nr_unused age_limit want_pages nr_negative dummy
func readDentryState(procRoot string) (total, unused, negative int64) {
	path := procRoot + "/sys/fs/dentry-state"
	f, err := os.Open(path)
	if err != nil {
		return -1, -1, -1
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return -1, -1, -1
	}

	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 {
		return -1, -1, -1
	}

	total, _ = strconv.ParseInt(fields[0], 10, 64)
	unused, _ = strconv.ParseInt(fields[1], 10, 64)
	negative, _ = strconv.ParseInt(fields[4], 10, 64)
	return total, unused, negative
}
