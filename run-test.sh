#!/bin/bash
# Test orchestrator: builds images, deploys workloads, and runs the stress test.
# Usage: ./run-test.sh [phase]
#   Phases: build, flood, pressure, collect, cleanup, all (default)

set -e

CTX="minikube"
NS="slab-stress-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

phase="${1:-all}"

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

phase_build() {
  log "=== Phase: Build images ==="

  log "Building dentry-flooder image..."
  minikube image build -t dentry-flooder:local "$SCRIPT_DIR/dentry-flooder"

  log "Building memory-pressure image..."
  minikube image build -t memory-pressure:local "$SCRIPT_DIR/memory-pressure"

  log "Images built successfully."
  minikube image ls | grep -E "dentry-flooder|memory-pressure"
}

phase_flood() {
  log "=== Phase: Flood dentries ==="

  # Ensure namespace exists
  kubectl --context "$CTX" apply -f "$SCRIPT_DIR/namespace.yaml"

  # Lower vfs_cache_pressure to make reclaim harder (increases lock hold time)
  log "Tuning kernel: vfs_cache_pressure=10"
  minikube ssh -- "sudo sysctl -w vm.vfs_cache_pressure=10" || true

  # Capture baseline
  log "Baseline slab stats:"
  minikube ssh -- "cat /proc/meminfo | grep -E 'Slab|SReclaimable'"
  minikube ssh -- "sudo cat /proc/slabinfo | awk '/^dentry/{print \"dentries:\", \$2}'"

  # Deploy flooders
  log "Deploying dentry flooder pods..."
  kubectl --context "$CTX" apply -f "$SCRIPT_DIR/deploy-flood.yaml"

  # Wait for flooding to complete
  log "Waiting for flooder pods to be ready..."
  kubectl --context "$CTX" -n "$NS" wait --for=condition=ready pod -l app=dentry-flooder --timeout=600s

  # Give them time to create files
  log "Waiting 30s for dentry creation to progress..."
  sleep 30

  # Check slab growth
  log "Post-flood slab stats:"
  minikube ssh -- "cat /proc/meminfo | grep -E 'Slab|SReclaimable'"
  minikube ssh -- "sudo cat /proc/slabinfo | awk '/^dentry/{print \"dentries:\", \$2}'"
  minikube ssh -- "sudo cat /proc/slabinfo | awk '/^inode_cache/{print \"inodes:\", \$2}'"
}

phase_pressure() {
  log "=== Phase: Apply memory pressure ==="

  # Delete previous job if it exists
  kubectl --context "$CTX" -n "$NS" delete job memory-pressure --ignore-not-found=true

  log "Deploying memory pressure job..."
  kubectl --context "$CTX" apply -f "$SCRIPT_DIR/deploy-pressure.yaml"

  log "Memory pressure applied. Watch monitor.sh output for node status changes."
  log "The memory pressure job will push the system into slab reclaim."

  # Wait a bit and check
  sleep 10
  log "Node status:"
  kubectl --context "$CTX" get nodes || echo "kubectl failed (node may be unresponsive)"

  log "Pod status:"
  kubectl --context "$CTX" -n "$NS" get pods || echo "kubectl failed"
}

phase_collect() {
  log "=== Phase: Collect diagnostics ==="

  mkdir -p "$SCRIPT_DIR/logs"
  ts=$(date +%Y%m%d_%H%M%S)

  log "Collecting dmesg..."
  minikube ssh -- "dmesg | tail -100" > "$SCRIPT_DIR/logs/dmesg_${ts}.log" 2>&1 || true

  log "Collecting slabinfo..."
  minikube ssh -- "sudo cat /proc/slabinfo" > "$SCRIPT_DIR/logs/slabinfo_${ts}.log" 2>&1 || true

  log "Collecting meminfo..."
  minikube ssh -- "cat /proc/meminfo" > "$SCRIPT_DIR/logs/meminfo_${ts}.log" 2>&1 || true

  log "Collecting node events..."
  kubectl --context "$CTX" get events -A --sort-by='.lastTimestamp' > "$SCRIPT_DIR/logs/events_${ts}.log" 2>&1 || true

  log "Collecting node describe..."
  kubectl --context "$CTX" describe node minikube > "$SCRIPT_DIR/logs/node_describe_${ts}.log" 2>&1 || true

  log "Diagnostics saved to $SCRIPT_DIR/logs/"
}

phase_cleanup() {
  log "=== Phase: Cleanup ==="

  kubectl --context "$CTX" delete namespace "$NS" --ignore-not-found=true --timeout=60s || true

  # Reset kernel tunable
  minikube ssh -- "sudo sysctl -w vm.vfs_cache_pressure=100" || true

  # Force drop caches to release dentries
  minikube ssh -- "sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'" || true

  log "Cleanup complete."
}

case "$phase" in
  build)    phase_build ;;
  flood)    phase_flood ;;
  pressure) phase_pressure ;;
  collect)  phase_collect ;;
  cleanup)  phase_cleanup ;;
  all)
    phase_build
    phase_flood
    phase_pressure
    sleep 30
    phase_collect
    log ""
    log "=== Test complete ==="
    log "Run './run-test.sh cleanup' when done investigating."
    log "Check logs/ directory for collected diagnostics."
    ;;
  *)
    echo "Usage: $0 {build|flood|pressure|collect|cleanup|all}"
    exit 1
    ;;
esac
