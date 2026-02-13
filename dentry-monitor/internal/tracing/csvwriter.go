package tracing

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	tsvHeader  = "timestamp\tpod\tcontainer\tcgroup_id\toperation\tpath\tfstype\n"
	tsvBufSize = 64 * 1024 // 64 KB write buffer
)

// TSVWriter writes trace events to tab-separated files with size-based rotation.
type TSVWriter struct {
	dir      string
	baseName string
	maxSize  int64
	maxFiles int

	mu      sync.Mutex
	file    *os.File
	buf     *bufio.Writer
	curSize int64
}

// NewTSVWriter creates a TSV writer that writes to dir/traces.tsv with rotation.
// maxSize is the maximum file size in bytes before rotation.
// maxFiles is the number of rotated files to keep.
func NewTSVWriter(dir string, maxSize int64, maxFiles int) (*TSVWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create trace dir: %w", err)
	}

	w := &TSVWriter{
		dir:      dir,
		baseName: "traces.tsv",
		maxSize:  maxSize,
		maxFiles: maxFiles,
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *TSVWriter) activePath() string {
	return filepath.Join(w.dir, w.baseName)
}

func (w *TSVWriter) rotatedPath(n int) string {
	return filepath.Join(w.dir, fmt.Sprintf("%s.%d", w.baseName, n))
}

func (w *TSVWriter) openFile() error {
	path := w.activePath()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open trace file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat trace file: %w", err)
	}

	w.file = f
	w.curSize = info.Size()
	w.buf = bufio.NewWriterSize(f, tsvBufSize)

	// Write header if file is empty (new or just rotated)
	if w.curSize == 0 {
		n, err := w.buf.WriteString(tsvHeader)
		if err != nil {
			return fmt.Errorf("write header: %w", err)
		}
		w.curSize += int64(n)
	}

	return nil
}

// WriteEvent writes a single trace event as a TSV line.
func (w *TSVWriter) WriteEvent(evt TraceEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	line := fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
		evt.Timestamp.Format(time.RFC3339Nano),
		evt.Pod,
		evt.Container,
		evt.CgroupID,
		evt.Operation,
		evt.Path,
		evt.Fstype,
	)

	n, err := w.buf.WriteString(line)
	if err != nil {
		return err
	}
	w.curSize += int64(n)

	if w.curSize >= w.maxSize {
		if err := w.rotate(); err != nil {
			log.Printf("tracing: rotation error: %v", err)
		}
	}

	return nil
}

func (w *TSVWriter) rotate() error {
	if err := w.buf.Flush(); err != nil {
		return fmt.Errorf("flush before rotate: %w", err)
	}
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close before rotate: %w", err)
	}

	// Remove the oldest rotated file if at capacity
	os.Remove(w.rotatedPath(w.maxFiles))

	// Shift rotated files: N-1 -> N, N-2 -> N-1, ..., 1 -> 2
	for i := w.maxFiles - 1; i >= 1; i-- {
		os.Rename(w.rotatedPath(i), w.rotatedPath(i+1))
	}

	// Move active file to .1
	os.Rename(w.activePath(), w.rotatedPath(1))

	return w.openFile()
}

// Flush flushes the buffered writer to disk.
func (w *TSVWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Flush()
}

// Close flushes and closes the underlying file.
func (w *TSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.buf.Flush(); err != nil {
		return err
	}
	return w.file.Close()
}
