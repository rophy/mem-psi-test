#!/bin/sh
# Memory pressure generator: allocates memory to force kernel slab reclaim.
# When the cgroup limit is hit, the kernel must shrink slab caches (dentries/inodes)
# via shrink_dcache_sb(), which holds spinlocks and can stall CPUs.
#
# Environment variables:
#   ALLOC_MB       - total memory to allocate in MiB (default: 3500)
#   CHUNK_MB       - allocation chunk size in MiB (default: 64)
#   ALLOC_WORKERS  - parallel allocation workers (default: 2)

set -e

ALLOC_MB="${ALLOC_MB:-3500}"
CHUNK_MB="${CHUNK_MB:-64}"
ALLOC_WORKERS="${ALLOC_WORKERS:-2}"

PER_WORKER_MB=$((ALLOC_MB / ALLOC_WORKERS))

echo "=== Memory Pressure Generator ==="
echo "Total allocation target: ${ALLOC_MB} MiB"
echo "Chunk size: ${CHUNK_MB} MiB"
echo "Workers: ${ALLOC_WORKERS} (${PER_WORKER_MB} MiB each)"
echo ""

pressure_worker() {
  worker_id=$1
  allocated=0
  # Allocate memory by reading /dev/zero into a file on tmpfs
  # This creates anonymous pages that count against the cgroup limit
  tmpdir="/dev/shm/pressure_${worker_id}"
  mkdir -p "$tmpdir"

  chunk=0
  while [ $allocated -lt "$PER_WORKER_MB" ]; do
    # Use dd to allocate a chunk; if OOM-killed or fails, that's expected
    dd if=/dev/zero of="${tmpdir}/chunk_${chunk}" bs=1M count="${CHUNK_MB}" 2>/dev/null || true
    allocated=$((allocated + CHUNK_MB))
    chunk=$((chunk + 1))
    echo "[worker ${worker_id}] allocated ${allocated}/${PER_WORKER_MB} MiB"
  done

  echo "[worker ${worker_id}] holding memory..."
  sleep infinity
}

echo "Starting memory pressure..."
for w in $(seq 1 "$ALLOC_WORKERS"); do
  pressure_worker "$w" &
done

wait
