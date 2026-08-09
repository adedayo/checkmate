//go:build unix

package util

import (
	"io/fs"
	"syscall"
)

// fileKey identifies a directory by its filesystem identity rather than by its
// path, which is the only way to recognise that two paths are the same
// directory. A symlink loop produces an unbounded supply of distinct paths for
// one inode, so a path-keyed guard would never fire.
type fileKey struct {
	device uint64
	inode  uint64
}

func fileKeyFor(info fs.FileInfo) (fileKey, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, true
}
