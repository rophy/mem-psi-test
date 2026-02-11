#!/bin/bash
# Monitor script: runs on the HOST to watch node status and slab metrics.
# Usage: ./monitor.sh [interval_seconds]

set -e

INTERVAL="${1:-5}"
CTX="minikube"
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
LOGFILE="${LOG_DIR}/monitor_$(date +%Y%m%d_%H%M%S).log"

log() {
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$ts] $*" | tee -a "$LOGFILE"
}

log "=== Slab Stress Test Monitor ==="
log "Polling every ${INTERVAL}s. Log: ${LOGFILE}"
log ""

while true; do
  log "--- tick ---"

  # Node status
  node_status=$(kubectl --context "$CTX" get nodes --no-headers 2>/dev/null || echo "KUBECTL_FAILED")
  log "Node: $node_status"

  # Check for NotReady
  if echo "$node_status" | grep -q "NotReady"; then
    log "*** NODE IS NOT READY ***"
    log "Collecting diagnostics..."

    # Dump events
    kubectl --context "$CTX" get events -A --sort-by='.lastTimestamp' 2>/dev/null \
      | tail -20 >> "$LOGFILE" 2>&1 || true

    # Dump node describe
    kubectl --context "$CTX" describe node minikube >> "$LOGFILE" 2>&1 || true
  fi

  # Slab stats via SSH
  slab_info=$(minikube ssh -- "cat /proc/meminfo | grep -E 'MemAvailable|Slab|SReclaimable|SUnreclaim'" 2>/dev/null || echo "SSH_FAILED")
  log "Memory: $slab_info"

  # Dentry/inode counts from slabinfo
  dentry_count=$(minikube ssh -- "sudo cat /proc/slabinfo | awk '/^dentry/{print \$2}'" 2>/dev/null || echo "?")
  inode_count=$(minikube ssh -- "sudo cat /proc/slabinfo | awk '/^inode_cache/{print \$2}'" 2>/dev/null || echo "?")
  log "Dentries: ${dentry_count}, Inodes: ${inode_count}"

  # Pod status
  pod_status=$(kubectl --context "$CTX" -n slab-stress-test get pods --no-headers 2>/dev/null || echo "NO_PODS")
  log "Pods: $(echo "$pod_status" | wc -l) total"

  log ""
  sleep "$INTERVAL"
done
