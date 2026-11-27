//go:build linux

package files

import (
	"io/fs"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// openedPath returns the path the kernel has for an open descriptor, so a
// path component swapped for a symlink between Resolve and open is caught.
func openedPath(f *os.File) (string, error) {
	return os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
}

// walkDirFlags opens a directory on the way down (see openNoFollow): O_PATH
// needs no read permission and opens nothing on the filesystem (no FUSE
// open on shfs); with O_DIRECTORY a symlink answers ENOTDIR.
const walkDirFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// lstatAt is Lstat of name inside the open directory dirfd (dirPath is its
// path, unused here): /proc/self/fd/<n> jumps to the directory itself (it is
// not a path that is looked up again), so nothing above name is resolved.
func lstatAt(dirfd int, _, name string) (fs.FileInfo, error) {
	return os.Lstat("/proc/self/fd/" + strconv.Itoa(dirfd) + "/" + name)
}
