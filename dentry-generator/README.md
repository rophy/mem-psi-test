# dentry-generator

Continuously generates kernel dentries at a configurable rate. Designed to
simulate MariaDB temp table churn that causes dentry cache bloat and eventually
CPU soft lockups on large-memory K8s nodes.

## Modes

- **negative** (default): create file → close → unlink. Leaves negative
  (unreferenced) dentries in the kernel dcache. Mimics MariaDB
  `CREATE TEMPORARY TABLE` / `DROP` cycles.
- **positive**: creates hard links sharing a single inode. Dentries persist
  as long as the files exist (~192 bytes each).

## Usage

### Standalone

```bash
# Compile
gcc -O2 -static -o dentry-generator dentry-generator.c

# Run at 1000 negative dentries/sec (runs until killed)
./dentry-generator /tmp/flood --rate 1000 --mode negative

# Run at 5000 positive dentries/sec, stop after 1M
./dentry-generator /tmp/flood --rate 5000 --mode positive --max 1000000
```

### Options

```
dentry-generator <base_path> [options]
  --rate N       target dentries per second (default: 1000)
  --mode M       "positive" or "negative" (default: negative)
  --per-dir N    entries per subdirectory (default: 50000)
  --max N        stop after N total dentries (default: unlimited)
```

### Container

```bash
# Build image (multi-stage, compiles from source)
docker build -t dentry-generator:local .

# Run in Docker
docker run --rm dentry-generator:local /tmp/flood --rate 2000 --mode negative

# Build in minikube
minikube image build -t dentry-generator:local .
```

### Kubernetes

```bash
kubectl apply -f deploy/deployment.yaml
```

Default deployment: 4 replicas, each generating 1000 negative dentries/sec
(4000/s total). Configure via container `args` in the deployment.

## Verifying unreferenced dentries

```bash
# Check dentry slab count on node
awk '/^dentry/{print $2}' /proc/slabinfo

# Reclaim unreferenced dentries
echo 2 > /proc/sys/vm/drop_caches

# If count drops after drop_caches, those were unreferenced (negative) dentries
```

## Output

```
dentry-generator: rate=1000/s, mode=negative, base=/tmp/dentry-flood
[     5s] total=5100  rate=1016/s (target=1000/s)
[    10s] total=10100  rate=1006/s (target=1000/s)
[    15s] total=15100  rate=1002/s (target=1000/s)
```

Progress is reported every 5 seconds. The generator handles SIGTERM gracefully
for clean pod shutdown.
