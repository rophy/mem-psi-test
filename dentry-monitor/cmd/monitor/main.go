package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	bpf "github.com/rophy/mem-psi-test/dentry-monitor/internal/ebpf"
	"github.com/rophy/mem-psi-test/dentry-monitor/internal/cgroupmap"
	"github.com/rophy/mem-psi-test/dentry-monitor/internal/metrics"
	"github.com/rophy/mem-psi-test/dentry-monitor/internal/tracing"
)

func main() {
	var (
		listenAddr      = flag.String("listen", ":9090", "HTTP listen address")
		procRoot        = flag.String("proc", "/proc", "Path to host /proc")
		cgroupRoot      = flag.String("cgroup", "/sys/fs/cgroup", "Path to host cgroup filesystem")
		pollInterval    = flag.Duration("poll-interval", 5*time.Second, "BPF map poll interval")
		resolveInterval = flag.Duration("resolve-interval", 30*time.Second, "Cgroup→pod resolve interval")
		traceBufferSize = flag.Int("trace-buffer", 10000, "Number of trace events to buffer")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("dentry-monitor starting")

	// Remove memlock rlimit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock rlimit: %v", err)
	}

	// Load eBPF objects
	objs, err := bpf.LoadObjects(nil)
	if err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach kprobes
	kpDalloc, err := link.Kprobe("d_alloc", objs.TraceDAlloc(), nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/d_alloc: %v", err)
	}
	defer kpDalloc.Close()
	log.Printf("attached kprobe/d_alloc")

	kpDallocPath, err := link.Kprobe("d_alloc", objs.TraceDAllocPath(), nil)
	if err != nil {
		log.Printf("warning: failed to attach kprobe/d_alloc (tracing): %v", err)
	} else {
		defer kpDallocPath.Close()
		log.Printf("attached kprobe/d_alloc (tracing)")
	}

	kpDinstantiate, err := link.Kprobe("d_instantiate", objs.TraceDInstantiate(), nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/d_instantiate: %v", err)
	}
	defer kpDinstantiate.Close()
	log.Printf("attached kprobe/d_instantiate")

	kpShrink, err := link.Kprobe("shrink_dcache_sb", objs.TraceShrinkDcache(), nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/shrink_dcache_sb: %v", err)
	}
	defer kpShrink.Close()
	log.Printf("attached kprobe/shrink_dcache_sb")

	// Start cgroup → pod resolver
	resolver := cgroupmap.NewResolver(*procRoot, *cgroupRoot)
	resolver.Start(*resolveInterval)
	defer resolver.Stop()

	// Start metrics collector
	collector := metrics.NewCollector(objs.DentryStatsMap(), objs.ReclaimCount(), resolver, *procRoot)
	prometheus.MustRegister(collector)

	stopCh := make(chan struct{})

	go collector.Start(*pollInterval, stopCh)
	log.Printf("metrics collector started (poll every %s)", *pollInterval)

	// Start trace consumer
	consumer := tracing.NewConsumer(objs.TraceEvents(), objs.TraceConfigMap(), resolver, *traceBufferSize)
	go consumer.Start(stopCh)
	log.Printf("trace consumer started (buffer size %d)", *traceBufferSize)

	// HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	traceHandler := tracing.NewHandler(consumer)
	traceHandler.RegisterRoutes(mux)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	server := &http.Server{
		Addr:    *listenAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("HTTP server listening on %s", *listenAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("received %v, shutting down", sig)

	close(stopCh)
	server.Close()
}
