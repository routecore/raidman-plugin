//go:build !linux

package files

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openedPath (non-Linux, development only): there is no /proc, so the opened
// name is resolved again and must still be the very file that is open.
func openedPath(f *os.File) (string, error) {
	p, err := filepath.EvalSymlinks(f.Name())
	if err != nil {
		return "", err
	}
	a, err := f.Stat()
	if err != nil {
		return "", err
	}
	b, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !os.SameFile(a, b) {
		return "", errors.New("file changed while opening")
	}
	return p, nil
}

// walkDirFlags (non-Linux): no O_PATH.
const walkDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// lstatAt (non-Linux, development only) goes by path: there is no
// /proc/self/fd to look up through the descriptor.
func lstatAt(_ int, dirPath, name string) (fs.FileInfo, error) {
	return os.Lstat(filepath.Join(dirPath, name))
}
