package tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
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
	Timestamp time.Time
	Pod       string
	Container string
	CgroupID  uint64
	Operation string
	Path      string
	Fstype    string
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
	Fstype    [16]byte
}

const depthRootFlag = 0x80000000

// TraceConfig controls tracing behavior.
type TraceConfig struct {
	Enabled      bool
	PathPatterns []string
}

// bpfTraceConfig matches the eBPF struct trace_config layout.
type bpfTraceConfig struct {
	Enabled uint32
	Pad     uint32
}

// Consumer reads trace events from the BPF ring buffer and writes them to a TSV file.
type Consumer struct {
	ringbufMap *ebpf.Map
	configMap  *ebpf.Map
	resolver   *cgroupmap.Resolver
	config     TraceConfig
	writer     *TSVWriter
}

// NewConsumer creates a trace event consumer that writes to the given TSV writer.
// It applies the trace config to the eBPF config map immediately.
func NewConsumer(ringbufMap, configMap *ebpf.Map, resolver *cgroupmap.Resolver, cfg TraceConfig, writer *TSVWriter) (*Consumer, error) {
	c := &Consumer{
		ringbufMap: ringbufMap,
		configMap:  configMap,
		resolver:   resolver,
		config:     cfg,
		writer:     writer,
	}
	if err := c.applyBPFConfig(); err != nil {
		return nil, fmt.Errorf("apply trace config: %w", err)
	}
	return c, nil
}

// applyBPFConfig pushes the trace config to the eBPF config map.
func (c *Consumer) applyBPFConfig() error {
	var bpfCfg bpfTraceConfig
	if c.config.Enabled {
		bpfCfg.Enabled = 1
	}
	var key uint32
	if err := c.configMap.Update(&key, &bpfCfg, ebpf.UpdateAny); err != nil {
		return err
	}
	log.Printf("tracing: config applied: enabled=%v patterns=%v", c.config.Enabled, c.config.PathPatterns)
	return nil
}

// Start begins consuming ring buffer events and writing them to the TSV file.
// Blocks until stopCh is closed.
func (c *Consumer) Start(stopCh <-chan struct{}) {
	rd, err := ringbuf.NewReader(c.ringbufMap)
	if err != nil {
		log.Printf("tracing: failed to create ring buffer reader: %v", err)
		return
	}
	defer rd.Close()

	// Periodic flush
	flushTicker := time.NewTicker(1 * time.Second)
	defer flushTicker.Stop()

	go func() {
		for {
			select {
			case <-flushTicker.C:
				if err := c.writer.Flush(); err != nil {
					log.Printf("tracing: flush error: %v", err)
				}
			case <-stopCh:
				return
			}
		}
	}()

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
			continue
		}

		// Resolve cgroup to pod
		info := c.resolver.Resolve(evt.CgroupID)
		path := buildPath(evt)

		// Userspace pattern filtering
		if len(c.config.PathPatterns) > 0 && !matchesAnyPattern(path, c.config.PathPatterns) {
			continue
		}

		var traceEvt TraceEvent
		traceEvt.Timestamp = time.Now()
		traceEvt.CgroupID = evt.CgroupID
		traceEvt.Operation = opName(evt.Operation)
		traceEvt.Path = path
		traceEvt.Fstype = extractString(evt.Fstype[:])

		if info != nil {
			traceEvt.Pod = info.Pod
			traceEvt.Container = info.Container
		}

		if err := c.writer.WriteEvent(traceEvt); err != nil {
			log.Printf("tracing: write error: %v", err)
		}
	}
}

// Close flushes and closes the TSV writer.
func (c *Consumer) Close() error {
	return c.writer.Close()
}

// buildPath reconstructs a path from the name components.
// Components are stored leaf-to-root, so we reverse them.
// Leading "/" means the path reached the real filesystem root (ext4/xfs/btrfs).
// No leading "/" means the path is partial (truncated or hit a virtual fs mount root).
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

func extractString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx > 0 {
		return string(b[:idx])
	}
	return ""
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
