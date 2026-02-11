#!/bin/sh
# Dentry flooder: creates millions of dentries using hard links.
# Hard links share a single inode, so the cost is ~192 bytes per dentry
# with negligible inode overhead. This maximizes dentry count per byte of RAM.
#
# Environment variables:
#   NUM_DIRS      - number of top-level directories (default: 200)
#   LINKS_PER_DIR - hard links per directory (default: 50000)
#   FLOOD_PATH    - base path for file creation (default: /tmp/dentry-flood)
#   PARALLEL      - number of parallel flood processes (default: 4)

NUM_DIRS="${NUM_DIRS:-200}"
LINKS_PER_DIR="${LINKS_PER_DIR:-50000}"
FLOOD_PATH="${FLOOD_PATH:-/tmp/dentry-flood}"
PARALLEL="${PARALLEL:-4}"

TOTAL=$((NUM_DIRS * LINKS_PER_DIR))
echo "=== Dentry Flooder (hard link mode) ==="
echo "Target: ${TOTAL} dentries (${NUM_DIRS} dirs x ${LINKS_PER_DIR} links)"
echo "Estimated slab cost: $((TOTAL * 192 / 1048576)) MiB"
echo "Path: ${FLOOD_PATH}"
echo "Parallel workers: ${PARALLEL}"
echo ""

mkdir -p "${FLOOD_PATH}"

# Create a single source file — all hard links share this inode
SRC="${FLOOD_PATH}/.src"
: > "$SRC"

flood_dir() {
  dir_idx=$1
  dir="${FLOOD_PATH}/d${dir_idx}"
  mkdir -p "$dir"
  i=0
  while [ $i -lt "$LINKS_PER_DIR" ]; do
    ln "$SRC" "${dir}/l${i}" 2>/dev/null || : > "${dir}/l${i}"
    i=$((i + 1))
  done
  echo "[worker] dir ${dir_idx}/${NUM_DIRS} done (${LINKS_PER_DIR} links)"
}

start_time=$(date +%s)

# Launch parallel workers
dir_idx=0
active=0
while [ $dir_idx -lt "$NUM_DIRS" ]; do
  flood_dir "$dir_idx" &
  dir_idx=$((dir_idx + 1))
  active=$((active + 1))
  if [ $active -ge "$PARALLEL" ]; then
    wait -n 2>/dev/null || wait
    active=$((active - 1))
  fi
done
wait

end_time=$(date +%s)
elapsed=$((end_time - start_time))

echo ""
echo "=== Flooding complete ==="
echo "Created ${TOTAL} dentries in ${elapsed}s"
echo "Sleeping to keep dentries alive..."

exec sleep infinity
