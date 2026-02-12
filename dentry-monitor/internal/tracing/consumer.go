package tracing

import (
	"bytes"
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/rophy/mem-psi-test/dentry-monitor/internal/cgroupmap"
)

// Operation type constants matching the eBPF program.
const (
	OpAlloc    = 0
	OpPositive = 1
	OpNegative = 2
)

// TraceEvent is a dentry trace event received from the eBPF ring buffer.
type TraceEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Pod       string    `json:"pod"`
	Namespace string    `json:"namespace"`
	Container string    `json:"container"`
	CgroupID  uint64    `json:"cgroup_id"`
	Operation string    `json:"operation"`
	Path      string    `json:"path"`
}

// rawTraceEvent matches the eBPF struct dentry_trace_event layout.
type rawTraceEvent struct {
	Timestamp uint64
	CgroupID  uint64
	Operation uint32
	PathLen   uint32
	Path      [256]byte
}

// TraceConfig controls tracing behavior.
// Pattern filtering and rate limiting are done in userspace.
type TraceConfig struct {
	Enabled      bool     `json:"enabled"`
	PathPatterns []string `json:"path_patterns"`
}

// bpfTraceConfig matches the eBPF struct trace_config layout.
type bpfTraceConfig struct {
	Enabled uint32
	Pad     uint32
}

// Consumer reads trace events from the BPF ring buffer and stores
// them in a circular buffer for HTTP API access.
type Consumer struct {
	ringbufMap   *ebpf.Map
	configMap    *ebpf.Map
	resolver     *cgroupmap.Resolver

	mu      sync.RWMutex
	buffer  []TraceEvent
	head    int  // next write position
	count   int  // total events in buffer
	bufSize int
	dropped uint64

	config TraceConfig
}

// NewConsumer creates a trace event consumer.
func NewConsumer(ringbufMap, configMap *ebpf.Map, resolver *cgroupmap.Resolver, bufSize int) *Consumer {
	return &Consumer{
		ringbufMap: ringbufMap,
		configMap:  configMap,
		resolver:   resolver,
		buffer:     make([]TraceEvent, bufSize),
		bufSize:    bufSize,
		config: TraceConfig{
			Enabled: false,
		},
	}
}

// Start begins consuming ring buffer events. Blocks until stopCh is closed.
func (c *Consumer) Start(stopCh <-chan struct{}) {
	rd, err := ringbuf.NewReader(c.ringbufMap)
	if err != nil {
		log.Printf("tracing: failed to create ring buffer reader: %v", err)
		return
	}
	defer rd.Close()

	go func() {
		<-stopCh
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				log.Printf("tracing: ring buffer read error: %v", err)
				return
			}
		}

		evt, err := parseRawEvent(record.RawSample)
		if err != nil {
			c.mu.Lock()
			c.dropped++
			c.mu.Unlock()
			continue
		}

		// Resolve cgroup to pod
		info := c.resolver.Resolve(evt.CgroupID)
		path := string(bytes.TrimRight(evt.Path[:evt.PathLen], "\x00"))

		// Userspace pattern filtering
		c.mu.RLock()
		patterns := c.config.PathPatterns
		c.mu.RUnlock()
		if len(patterns) > 0 && !matchesAnyPattern(path, patterns) {
			continue
		}

		var traceEvt TraceEvent
		traceEvt.Timestamp = time.Now() // Use wall clock for JSON output
		traceEvt.CgroupID = evt.CgroupID
		traceEvt.Operation = opName(evt.Operation)
		traceEvt.Path = path

		if info != nil {
			traceEvt.Pod = info.Pod
			traceEvt.Namespace = info.Namespace
			traceEvt.Container = info.Container
		} else {
			traceEvt.Pod = "unknown"
			traceEvt.Namespace = "unknown"
			traceEvt.Container = "unknown"
		}

		c.mu.Lock()
		c.buffer[c.head] = traceEvt
		c.head = (c.head + 1) % c.bufSize
		if c.count < c.bufSize {
			c.count++
		}
		c.mu.Unlock()
	}
}

// GetEvents returns recent trace events, optionally filtered.
func (c *Consumer) GetEvents(filter EventFilter) EventsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var events []TraceEvent

	// Read from circular buffer in chronological order
	start := 0
	if c.count == c.bufSize {
		start = c.head // buffer is full, oldest is at head
	}

	for i := 0; i < c.count; i++ {
		idx := (start + i) % c.bufSize
		evt := c.buffer[idx]

		// Apply filters
		if filter.Pod != "" && evt.Pod != filter.Pod {
			continue
		}
		if filter.Namespace != "" && evt.Namespace != filter.Namespace {
			continue
		}
		if filter.PathSubstring != "" && !containsSubstring(evt.Path, filter.PathSubstring) {
			continue
		}
		if !filter.Since.IsZero() && evt.Timestamp.Before(filter.Since) {
			continue
		}

		events = append(events, evt)

		if filter.Limit > 0 && len(events) >= filter.Limit {
			break
		}
	}

	if events == nil {
		events = []TraceEvent{}
	}

	return EventsResponse{
		Events:     events,
		Total:      len(events),
		BufferSize: c.bufSize,
		Dropped:    c.dropped,
	}
}

// GetConfig returns the current trace configuration.
func (c *Consumer) GetConfig() TraceConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

// SetConfig updates the trace configuration and pushes it to the BPF map.
func (c *Consumer) SetConfig(cfg TraceConfig) error {
	var bpfCfg bpfTraceConfig
	if cfg.Enabled {
		bpfCfg.Enabled = 1
	}

	var key uint32
	if err := c.configMap.Update(&key, &bpfCfg, ebpf.UpdateAny); err != nil {
		return err
	}

	c.mu.Lock()
	c.config = cfg
	c.mu.Unlock()

	log.Printf("tracing: config updated: enabled=%v patterns=%v",
		cfg.Enabled, cfg.PathPatterns)
	return nil
}

// EventFilter controls which events are returned by GetEvents.
type EventFilter struct {
	Pod           string
	Namespace     string
	PathSubstring string
	Limit         int
	Since         time.Time
}

// EventsResponse is the JSON response for GET /traces.
type EventsResponse struct {
	Events     []TraceEvent `json:"events"`
	Total      int          `json:"total"`
	BufferSize int          `json:"buffer_size"`
	Dropped    uint64       `json:"dropped"`
}

func parseRawEvent(data []byte) (*rawTraceEvent, error) {
	var evt rawTraceEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
		return nil, err
	}
	return &evt, nil
}

func opName(op uint32) string {
	switch op {
	case OpAlloc:
		return "alloc"
	case OpPositive:
		return "positive"
	case OpNegative:
		return "negative"
	default:
		return "unknown"
	}
}

func containsSubstring(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func matchesAnyPattern(path string, patterns []string) bool {
	for _, pat := range patterns {
		if containsSubstring(path, pat) {
			return true
		}
	}
	return false
}
