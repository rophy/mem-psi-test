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
  log "Tuning kernel: vfs_cache_pressure=1 (hoard dentries, force large batch reclaim)"
  minikube ssh -- "sudo sysctl -w vm.vfs_cache_pressure=1" || true

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

  # Delete previous deployment if it exists
  kubectl --context "$CTX" -n "$NS" delete deployment memory-pressure --ignore-not-found=true

  log "Deploying memory pressure pods..."
  kubectl --context "$CTX" apply -f "$SCRIPT_DIR/deploy-pressure.yaml"

  log "Waiting for pressure pods to start..."
  kubectl --context "$CTX" -n "$NS" wait --for=condition=ready pod -l app=memory-pressure --timeout=120s || true

  log "Memory pressure pods running. Monitoring node status..."

  # Monitor for 2 minutes, checking every 10s
  for i in $(seq 1 12); do
    log "--- check $i/12 ---"
    node_status=$(kubectl --context "$CTX" get nodes --no-headers 2>/dev/null || echo "KUBECTL FAILED")
    log "Node: $node_status"

    mem_info=$(minikube ssh -- "cat /proc/meminfo | grep -E 'MemAvailable|Slab|SReclaimable'" 2>/dev/null || echo "SSH FAILED")
    log "Memory: $mem_info"

    pod_summary=$(kubectl --context "$CTX" -n "$NS" get pods --no-headers 2>/dev/null | wc -l || echo "?")
    log "Pods: $pod_summary total"

    if echo "$node_status" | grep -q "NotReady"; then
      log "*** NODE NOT READY DETECTED ***"
      break
    fi

    sleep 10
  done
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
