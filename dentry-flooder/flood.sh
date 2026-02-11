#!/bin/sh
# Dentry flooder: creates millions of files to inflate dentry/inode slab caches.
# Each file creates a dentry + inode entry in the kernel slab allocator.
#
# Environment variables:
#   NUM_DIRS      - number of top-level directories (default: 50)
#   FILES_PER_DIR - files to create per directory (default: 100000)
#   FLOOD_PATH    - base path for file creation (default: /tmp/dentry-flood)
#   PARALLEL      - number of parallel flood processes (default: 4)

set -e

NUM_DIRS="${NUM_DIRS:-50}"
FILES_PER_DIR="${FILES_PER_DIR:-100000}"
FLOOD_PATH="${FLOOD_PATH:-/tmp/dentry-flood}"
PARALLEL="${PARALLEL:-4}"

TOTAL=$((NUM_DIRS * FILES_PER_DIR))
echo "=== Dentry Flooder ==="
echo "Creating ${TOTAL} files (${NUM_DIRS} dirs x ${FILES_PER_DIR} files)"
echo "Path: ${FLOOD_PATH}"
echo "Parallel workers: ${PARALLEL}"
echo ""

flood_dir() {
  dir_idx=$1
  dir="${FLOOD_PATH}/d${dir_idx}"
  mkdir -p "$dir"
  i=0
  while [ $i -lt "$FILES_PER_DIR" ]; do
    : > "${dir}/f${i}"
    i=$((i + 1))
  done
  echo "[worker] dir ${dir_idx}/${NUM_DIRS} done (${FILES_PER_DIR} files)"
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
echo "Created ${TOTAL} files in ${elapsed}s"
echo "Files are held open in cache. Sleeping to keep dentries alive..."

# Keep the pod running so dentries stay cached
exec sleep infinity
