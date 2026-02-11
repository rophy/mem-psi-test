#!/bin/bash
# Benchmark: measure dentry reclaim time via tmpfs unmount.
#
# Creates dentries on a tmpfs mount using a compiled C tool, then unmounts it.
# Unmount calls shrink_dcache_for_umount() — the exact code path that
# causes CPU soft lockups in production when containers are destroyed.
#
# Prerequisites: compile dentry-creator.c and copy to minikube:
#   gcc -O2 -static -o /tmp/dentry-creator dentry-creator.c
#   minikube cp /tmp/dentry-creator minikube:/tmp/dentry-creator
#   minikube ssh -- "sudo chmod +x /tmp/dentry-creator"
#
# Usage: ./benchmark-reclaim.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MNT="/tmp/dentry-bench-mnt"
CREATOR="/tmp/dentry-creator"

# Dentry counts to benchmark (ascending).
STEPS="100000 500000 1000000 2000000 5000000 10000000"

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

ssh_cmd() {
  minikube ssh -- "$@" 2>/dev/null | tr -d '\r'
}

ensure_creator() {
  # Check if creator binary exists in VM
  if ssh_cmd "test -x ${CREATOR}" | grep -q ""; then
    return 0
  fi

  log "Compiling dentry-creator..."
  gcc -O2 -static -o /tmp/dentry-creator "$SCRIPT_DIR/dentry-creator.c"
  minikube cp /tmp/dentry-creator minikube:${CREATOR}
  ssh_cmd "sudo chmod +x ${CREATOR}"
  log "dentry-creator ready"
}

get_dentry_count() {
  ssh_cmd "sudo cat /proc/slabinfo" | awk '/^dentry/{print $2}'
}

time_unmount() {
  ssh_cmd "sudo sh -c '
    start=\$(date +%s%N)
    umount ${MNT}
    end=\$(date +%s%N)
    echo \$((end - start))
  '"
}

# Ensure binary is available
ensure_creator

# Header
log "=== Dentry Reclaim Benchmark ==="
log ""
log "Kernel: $(ssh_cmd 'uname -r')"
log "Memory: $(ssh_cmd 'grep MemTotal /proc/meminfo')"
log "CPUs:   $(ssh_cmd 'nproc')"
log ""
log "Method: create hard links on tmpfs (C tool), then time umount"
log "Code path: shrink_dcache_for_umount() — same as container destruction"
log ""

# Disable vfs_cache_pressure so kernel hoards dentries
ssh_cmd "sudo sysctl -w vm.vfs_cache_pressure=0" > /dev/null

printf "%-12s %-15s %-15s %-12s %-18s %-18s\n" \
  "TARGET" "BEFORE_UMOUNT" "AFTER_UMOUNT" "RECLAIMED" "UMOUNT_TIME" "EXTRAP_1.5B"
printf "%-12s %-15s %-15s %-12s %-18s %-18s\n" \
  "------" "------------" "-----------" "---------" "-----------" "-----------"

results=()

for target in $STEPS; do
  log "Creating ${target} dentries on tmpfs..."

  # Clean up any previous mount
  ssh_cmd "sudo umount ${MNT}" > /dev/null 2>&1 || true
  ssh_cmd "sudo rm -rf ${MNT}" > /dev/null 2>&1 || true

  # Check available memory
  avail_kb=$(ssh_cmd "awk '/MemAvailable/{print \$2}' /proc/meminfo")
  needed_kb=$((target * 192 / 1024 + 100000))
  if [ "$needed_kb" -gt "$avail_kb" ]; then
    log "SKIP ${target}: need ~${needed_kb}KB but only ${avail_kb}KB available"
    continue
  fi

  # Mount tmpfs with enough space and unlimited inodes.
  # Hard links share one inode but directory entries cost ~128 bytes each in tmpfs.
  tmpfs_mb=$(( (target * 128 / 1024 / 1024) + 64 ))
  # Cap at available memory minus 500MB headroom
  max_tmpfs_mb=$(( (avail_kb / 1024) - 500 ))
  if [ "$tmpfs_mb" -gt "$max_tmpfs_mb" ]; then
    tmpfs_mb=$max_tmpfs_mb
  fi
  ssh_cmd "sudo mkdir -p ${MNT} && sudo mount -t tmpfs -o size=${tmpfs_mb}m,nr_inodes=0 tmpfs ${MNT}"

  # Create dentries using C tool
  creation_output=$(ssh_cmd "sudo ${CREATOR} ${MNT} ${target}")
  log "$creation_output"

  # Get dentry count before unmount
  before=$(get_dentry_count)
  log "Kernel dentries before unmount: ${before}"

  # Time the unmount
  elapsed_ns=$(time_unmount)
  elapsed_ms=$((elapsed_ns / 1000000))

  # Get dentry count after unmount
  after=$(get_dentry_count)

  reclaimed=$((before - after))

  # Calculate ns per dentry
  if [ "$reclaimed" -gt 0 ]; then
    ns_per_dentry=$((elapsed_ns / reclaimed))
    extrap_ms=$(echo "1500000000 * $ns_per_dentry / 1000000" | bc)
    extrap_s=$((extrap_ms / 1000))
  else
    ns_per_dentry=0
    extrap_s=0
  fi

  printf "%-12s %-15s %-15s %-12s %-18s %-18s\n" \
    "$target" "$before" "$after" "$reclaimed" "${elapsed_ms}ms" "${extrap_s}s"

  results+=("${target}:${reclaimed}:${elapsed_ms}:${ns_per_dentry}:${extrap_s}")
done

# Reset kernel tunable
ssh_cmd "sudo sysctl -w vm.vfs_cache_pressure=100" > /dev/null

log ""
log "=== Summary ==="
log ""
log "Soft lockup threshold: ~20 seconds (2 * kernel.watchdog_thresh)"
log ""

for r in "${results[@]}"; do
  IFS=':' read -r target reclaimed ms ns extrap <<< "$r"
  if [ "$extrap" -ge 20 ]; then
    verdict=">> WOULD SOFT LOCKUP <<"
  elif [ "$extrap" -ge 10 ]; then
    verdict="RISKY (close to threshold)"
  else
    verdict="ok"
  fi
  log "  ${reclaimed} dentries reclaimed in ${ms}ms (${ns}ns/dentry)"
  log "    → 1.5B extrapolation: ${extrap}s [${verdict}]"
  log ""
done

log "Note: production nodes with NUMA topology and multiple CPUs contending"
log "on the same spinlock will likely see WORSE performance than measured here."
