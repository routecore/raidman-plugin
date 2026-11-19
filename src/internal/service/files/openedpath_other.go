//go:build !linux

package files

import (
	"errors"
	"os"
	"path/filepath"
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
