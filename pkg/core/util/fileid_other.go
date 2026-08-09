//go:build !unix

package util

import "io/fs"

// fileKey identifies a directory on platforms without a stable, cheaply
// readable (device, inode) pair.
//
// On Windows the true identity is the volume serial number plus file index,
// which requires an open handle and GetFileInformationByHandle — a syscall per
// directory and a dependency this package does not otherwise need.
//
// Until that is worth adding, identity is reported as *unavailable* and the
// walker falls back on maxWalkDepth to guarantee termination. Reporting it
// unavailable rather than guessing from, say, size and modification time is
// the safe direction: a false positive would silently skip a real directory
// and lose findings, whereas a false negative only means the depth cap does
// the work instead.
type fileKey struct {
	device uint64
	inode  uint64
}

func fileKeyFor(fs.FileInfo) (fileKey, bool) {
	return fileKey{}, false
}
