package cgroupmap

import (
	"os"
	"syscall"
)

// statIno extracts the inode number from a FileInfo on Linux.
func statIno(info os.FileInfo) (uint64, bool) {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return sys.Ino, true
}
