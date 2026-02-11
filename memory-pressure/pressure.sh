#!/bin/sh
# Memory pressure generator: allocates anonymous memory via a memory-backed volume.
# The volume is mounted at /mem, backed by tmpfs (emptyDir medium: Memory).
# Writing here creates anonymous pages charged to the pod's cgroup, contributing
# to overall node memory pressure.
#
# Environment variables:
#   ALLOC_MB       - total memory to allocate in MiB (default: 512)
#   CHUNK_MB       - allocation chunk size in MiB (default: 32)

set -e

ALLOC_MB="${ALLOC_MB:-512}"
CHUNK_MB="${CHUNK_MB:-32}"

echo "=== Memory Pressure Generator ==="
echo "Allocation target: ${ALLOC_MB} MiB"
echo "Chunk size: ${CHUNK_MB} MiB"
echo "Writing to /mem (memory-backed emptyDir)"
echo ""

allocated=0
chunk=0
while [ "$allocated" -lt "$ALLOC_MB" ]; do
  remaining=$((ALLOC_MB - allocated))
  if [ "$remaining" -lt "$CHUNK_MB" ]; then
    size="$remaining"
  else
    size="$CHUNK_MB"
  fi
  dd if=/dev/zero of="/mem/chunk_${chunk}" bs=1M count="${size}" 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "dd failed at ${allocated} MiB (likely OOM or tmpfs full)"
    break
  fi
  allocated=$((allocated + size))
  chunk=$((chunk + 1))
  echo "allocated ${allocated}/${ALLOC_MB} MiB"
done

echo ""
echo "Holding ${allocated} MiB in memory. Sleeping..."
exec sleep infinity
