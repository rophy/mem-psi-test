package tracing

import (
	"bytes"
	"encoding/binary"
	"log"
	"strings"
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
	Container string    `json:"container"`
	CgroupID  uint64    `json:"cgroup_id"`
	Operation string    `json:"operation"`
	Path      string    `json:"path"`
}

// rawTraceEvent matches the eBPF struct dentry_trace_event layout.
// Path components are stored leaf-to-root: names[0]=filename, names[1]=parent, etc.
// Bit 31 of Depth is set if the walk reached the filesystem root.
type rawTraceEvent struct {
	Timestamp uint64
	CgroupID  uint64
	Operation uint32
	Depth     uint32
	Names     [8][64]byte
}

const depthRootFlag = 0x80000000

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

	// Subscribers for SSE streaming
	subMu   sync.Mutex
	subs    map[uint64]chan TraceEvent
	nextSub uint64
}

// NewConsumer creates a trace event consumer.
func NewConsumer(ringbufMap, configMap *ebpf.Map, resolver *cgroupmap.Resolver, bufSize int) *Consumer {
	return &Consumer{
		ringbufMap: ringbufMap,
		configMap:  configMap,
		resolver:   resolver,
		buffer:     make([]TraceEvent, bufSize),
		bufSize:    bufSize,
		subs:       make(map[uint64]chan TraceEvent),
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
		path := buildPath(evt)

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
			traceEvt.Container = info.Container
		}

		c.mu.Lock()
		c.buffer[c.head] = traceEvt
		c.head = (c.head + 1) % c.bufSize
		if c.count < c.bufSize {
			c.count++
		}
		c.mu.Unlock()

		// Fan out to SSE subscribers (non-blocking)
		c.subMu.Lock()
		for _, ch := range c.subs {
			select {
			case ch <- traceEvt:
			default:
				// subscriber too slow, drop event
			}
		}
		c.subMu.Unlock()
	}
}

// Subscribe returns a channel that receives live trace events.
// Call Unsubscribe with the returned ID when done.
func (c *Consumer) Subscribe(bufSize int) (uint64, <-chan TraceEvent) {
	ch := make(chan TraceEvent, bufSize)
	c.subMu.Lock()
	id := c.nextSub
	c.nextSub++
	c.subs[id] = ch
	c.subMu.Unlock()
	return id, ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (c *Consumer) Unsubscribe(id uint64) {
	c.subMu.Lock()
	if ch, ok := c.subs[id]; ok {
		delete(c.subs, id)
		close(ch)
	}
	c.subMu.Unlock()
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

// buildPath reconstructs a full path from the name components.
// Components are stored leaf-to-root, so we reverse them.
// If the eBPF walk reached the filesystem root, the path starts with "/".
// Otherwise (truncated), no leading "/" signals a partial path.
func buildPath(evt *rawTraceEvent) string {
	reachedRoot := evt.Depth&depthRootFlag != 0
	depth := int(evt.Depth &^ depthRootFlag)
	if depth > 8 {
		depth = 8
	}
	parts := make([]string, 0, depth)
	for i := depth - 1; i >= 0; i-- {
		slot := evt.Names[i][:]
		// Find first null — ringbuf memory is uninitialized after the null terminator
		if idx := bytes.IndexByte(slot, 0); idx > 0 {
			name := string(slot[:idx])
			if name != "/" {
				parts = append(parts, name)
			}
		}
	}
	if len(parts) == 0 {
		return "/"
	}
	if reachedRoot {
		return "/" + strings.Join(parts, "/")
	}
	return strings.Join(parts, "/")
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
