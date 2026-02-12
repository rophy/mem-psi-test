package cgroupmap

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PodInfo holds resolved pod metadata for a cgroup ID.
type PodInfo struct {
	Pod       string
	Container string
	CgroupID  uint64
}

// Resolver maps kernel cgroup IDs to Kubernetes pod metadata.
// It works by scanning /proc/<pid>/cgroup and matching against
// known cgroup paths from /sys/fs/cgroup.
type Resolver struct {
	mu       sync.RWMutex
	cache    map[uint64]*PodInfo // cgroup_id → pod info
	procRoot string             // usually "/proc" (or host-mounted path)
	cgRoot   string             // usually "/sys/fs/cgroup"
	stopCh   chan struct{}
}

// NewResolver creates a resolver that scans the host proc and cgroup
// filesystems. Pass the paths where they are mounted in the container
// (e.g. /host/proc, /host/sys/fs/cgroup).
func NewResolver(procRoot, cgRoot string) *Resolver {
	return &Resolver{
		cache:    make(map[uint64]*PodInfo),
		procRoot: procRoot,
		cgRoot:   cgRoot,
		stopCh:   make(chan struct{}),
	}
}

// Start begins periodic scanning. Call Stop() to terminate.
func (r *Resolver) Start(interval time.Duration) {
	r.refresh()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.refresh()
			case <-r.stopCh:
				return
			}
		}
	}()
}

// Stop terminates the background refresh goroutine.
func (r *Resolver) Stop() {
	close(r.stopCh)
}

// Resolve returns pod info for a cgroup ID, or nil if unknown.
func (r *Resolver) Resolve(cgroupID uint64) *PodInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cache[cgroupID]
}

// Snapshot returns a copy of all known mappings.
func (r *Resolver) Snapshot() map[uint64]*PodInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint64]*PodInfo, len(r.cache))
	for k, v := range r.cache {
		out[k] = v
	}
	return out
}

// refresh scans /proc to build cgroup_id → pod mapping.
// For cgroup v2 (unified hierarchy), we stat the cgroup directory
// to get the inode number which matches bpf_get_current_cgroup_id().
func (r *Resolver) refresh() {
	newCache := make(map[uint64]*PodInfo)

	entries, err := os.ReadDir(r.procRoot)
	if err != nil {
		log.Printf("resolver: cannot read %s: %v", r.procRoot, err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == 0 {
			continue
		}

		cgroupPath := filepath.Join(r.procRoot, entry.Name(), "cgroup")
		cgDir := r.parseCgroupV2(cgroupPath)
		if cgDir == "" {
			continue
		}

		// Extract pod info from cgroup path
		info := r.parsePodFromCgroupPath(cgDir)
		if info == nil {
			continue
		}

		// Get cgroup ID by stat()ing the cgroup directory
		fullCgPath := filepath.Join(r.cgRoot, cgDir)
		var stat os.FileInfo
		stat, err = os.Stat(fullCgPath)
		if err != nil {
			continue
		}

		// The cgroup ID from bpf_get_current_cgroup_id() is the inode
		// number of the cgroup directory in cgroupfs.
		sys, ok := statIno(stat)
		if !ok {
			continue
		}

		info.CgroupID = sys
		newCache[sys] = info
	}

	r.mu.Lock()
	r.cache = newCache
	r.mu.Unlock()

	log.Printf("resolver: refreshed, %d cgroup→pod mappings", len(newCache))
}

// parseCgroupV2 reads /proc/<pid>/cgroup and returns the cgroup v2 path.
// Format: "0::/path/to/cgroup"
//
// When reading host /proc from inside a container, the path may be relative
// to the container's own cgroup (e.g. "/../../../burstable/pod.../container").
// We clean the path and, if needed, prepend "/kubepods" to reconstruct the
// absolute cgroup path.
func (r *Resolver) parseCgroupV2(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 line: "0::<path>"
		if strings.HasPrefix(line, "0::") {
			cgPath := strings.TrimPrefix(line, "0::")
			// Clean relative paths (e.g. "/../../../burstable/pod.../cid")
			cgPath = filepath.Clean(cgPath)
			// If the path lost its "kubepods" prefix due to relative traversal,
			// try to reconstruct it by finding where "burstable" or "besteffort"
			// or "guaranteed" appears and prepending "/kubepods".
			if !strings.Contains(cgPath, "kubepods") {
				for _, qos := range []string{"/burstable/", "/besteffort/", "/guaranteed/"} {
					if idx := strings.Index(cgPath, qos); idx >= 0 {
						cgPath = "/kubepods" + cgPath[idx:]
						break
					}
				}
			}
			return cgPath
		}
	}
	return ""
}

// parsePodFromCgroupPath extracts pod/namespace/container from a
// Kubernetes cgroup path. Typical patterns:
//
// systemd cgroup driver:
//
//	/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
//
// cgroupfs driver:
//
//	/kubepods/burstable/pod<uid>/<container-id>
func (r *Resolver) parsePodFromCgroupPath(cgPath string) *PodInfo {
	// Must contain "kubepods" somewhere
	if !strings.Contains(cgPath, "kubepods") {
		return nil
	}

	parts := strings.Split(cgPath, "/")
	var podUID, containerID string

	for _, part := range parts {
		// Look for pod UID
		if idx := strings.Index(part, "pod"); idx >= 0 {
			// Extract UID after "pod"
			rest := part[idx+3:]
			// Remove .slice suffix if present
			rest = strings.TrimSuffix(rest, ".slice")
			if rest != "" {
				podUID = rest
			}
		}
		// Look for container ID (last component, usually a hex string or cri-containerd-<id>.scope)
		if strings.HasPrefix(part, "cri-containerd-") {
			containerID = strings.TrimPrefix(part, "cri-containerd-")
			containerID = strings.TrimSuffix(containerID, ".scope")
		} else if len(part) == 64 {
			// Plain container ID (64 hex chars)
			containerID = part
		}
	}

	if podUID == "" {
		return nil
	}

	// We have cgroup-level info. The actual pod name/namespace must come
	// from K8s API. For now, use the pod UID and container ID as identifiers.
	// A production implementation would use client-go to resolve these.
	info := &PodInfo{
		Pod:       fmt.Sprintf("pod-%s", shortenUID(podUID)),
		Container: containerID,
	}

	return info
}

func shortenUID(uid string) string {
	// Convert Kubernetes UID format (with underscores from systemd) to dashes
	uid = strings.ReplaceAll(uid, "_", "-")
	if len(uid) > 12 {
		return uid[:12]
	}
	return uid
}

