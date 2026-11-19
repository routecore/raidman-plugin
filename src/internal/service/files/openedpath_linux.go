//go:build linux

package files

import (
	"os"
	"strconv"
)

// openedPath returns the path the kernel has for an open descriptor, so a
// path component swapped for a symlink between Resolve and open is caught.
func openedPath(f *os.File) (string, error) {
	return os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
}
