// Package files is a read-only file browser over the Unraid data and flash
// mounts.
//
// Allowed: /mnt/user, /mnt/user0, /mnt/disk<N>, /mnt/cache, /mnt/<pool>
// (pools from /boot/config/pools/*.cfg) and /boot. Every path is checked
// twice: lexically on the client's input (so nothing outside the roots is
// even stat'ed) and again after all symlinks are resolved (a link inside a
// share that points to /etc is refused). Opened files are checked a third
// time through the open descriptor (see openedPath), so swapping a path
// component for a symlink after the check does not escape the roots.
package files

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// Overridable in tests.
var (
	MntDir     = "/mnt"
	BootDir    = "/boot"
	PoolsDir   = "/boot/config/pools"
	MaxEntries = 5000
)

var (
	diskRe     = regexp.MustCompile(`^disk[0-9]+$`)
	poolNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	// Names under /mnt that are never pools (Unassigned Devices, remote
	// mounts, the root share and the user shares themselves).
	reservedMnt = map[string]bool{"disks": true, "remotes": true, "addons": true, "rootshare": true, "user": true, "user0": true}
)

var (
	errForbidden = &httperr.Error{Status: http.StatusForbidden, Msg: "path not allowed"}
	// 422, not 404: the app reads a plugin 404 as "route missing (old plugin)".
	errNotFound = &httperr.Error{Status: http.StatusUnprocessableEntity, Msg: "path not found"}
)

// Entry is one directory entry. Mtime is Unix epoch seconds.
type Entry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Type  string `json:"type"` // dir | file | symlink
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"`
	// TargetType is "dir" or "file" for a symlink whose target is itself
	// allowed; omitted otherwise.
	TargetType string `json:"targetType,omitempty"`
}

// Listing is the GET /api/files/list response.
type Listing struct {
	Path      string  `json:"path"`
	Parent    *string `json:"parent"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated,omitempty"`
}

// pools returns the pool names from /boot/config/pools/*.cfg.
func pools() map[string]bool {
	out := map[string]bool{}
	matches, _ := filepath.Glob(filepath.Join(PoolsDir, "*.cfg"))
	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), ".cfg")
		if poolNameRe.MatchString(name) && !reservedMnt[name] {
			out[name] = true
		}
	}
	return out
}

// bases returns the configured mount bases and their symlink-resolved forms.
func bases(dir string) []string {
	out := []string{filepath.Clean(dir)}
	if r, err := filepath.EvalSymlinks(dir); err == nil && r != out[0] {
		out = append(out, r)
	}
	return out
}

// under reports whether p is base or inside it (separator boundary, so
// /bootleg is not under /boot).
func under(p, base string) bool {
	return p == base || strings.HasPrefix(p, base+"/")
}

// rootOf returns the allowed root that contains the clean absolute path p,
// or "" when p is outside every root.
func rootOf(p string, poolSet map[string]bool) string {
	for _, b := range bases(BootDir) {
		if under(p, b) {
			return b
		}
	}
	for _, b := range bases(MntDir) {
		if !strings.HasPrefix(p, b+"/") {
			continue
		}
		seg, _, _ := strings.Cut(strings.TrimPrefix(p, b+"/"), "/")
		if seg == "user" || seg == "user0" || seg == "cache" || diskRe.MatchString(seg) || poolSet[seg] {
			return b + "/" + seg
		}
	}
	return ""
}

// Allowed reports whether the clean absolute path p is inside a root.
func Allowed(p string) bool { return rootOf(p, pools()) != "" }

// Resolve validates a client path and returns its canonical form (all
// symlinks resolved). 400: empty, relative or NUL; 403: ".." segments or
// outside the roots (before or after resolving); 404: missing.
func Resolve(raw string) (string, error) {
	if raw == "" {
		return "", httperr.New(http.StatusBadRequest, "path missing")
	}
	if strings.ContainsRune(raw, 0) || !strings.HasPrefix(raw, "/") {
		return "", httperr.New(http.StatusBadRequest, "invalid path")
	}
	for _, seg := range strings.Split(raw, "/") {
		if seg == ".." {
			return "", errForbidden
		}
	}
	poolSet := pools()
	clean := filepath.Clean(raw)
	if rootOf(clean, poolSet) == "" {
		return "", errForbidden
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", errNotFound
		}
		if errors.Is(err, fs.ErrPermission) {
			return "", errForbidden
		}
		return "", err
	}
	if rootOf(resolved, poolSet) == "" {
		return "", errForbidden
	}
	return resolved, nil
}

func entryType(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	}
	return "file"
}

// List returns a directory's entries: directories first, then by name
// (case-insensitive), at most MaxEntries (Truncated set beyond that).
func List(raw string) (Listing, error) {
	p, err := Resolve(raw)
	if err != nil {
		return Listing{}, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return Listing{}, errNotFound
	}
	if !fi.IsDir() {
		return Listing{}, httperr.New(http.StatusBadRequest, "not a directory")
	}
	des, err := os.ReadDir(p)
	if err != nil && len(des) == 0 {
		if errors.Is(err, fs.ErrPermission) {
			return Listing{}, errForbidden
		}
		return Listing{}, err
	}
	sort.SliceStable(des, func(i, j int) bool {
		di, dj := des[i].IsDir(), des[j].IsDir()
		if di != dj {
			return di
		}
		a, b := strings.ToLower(des[i].Name()), strings.ToLower(des[j].Name())
		if a != b {
			return a < b
		}
		return des[i].Name() < des[j].Name()
	})
	out := Listing{Path: p, Entries: make([]Entry, 0, min(len(des), MaxEntries))}
	if len(des) > MaxEntries {
		des = des[:MaxEntries]
		out.Truncated = true
	}
	poolSet := pools()
	if root := rootOf(p, poolSet); root != "" && p != root {
		parent := filepath.Dir(p)
		out.Parent = &parent
	}
	for _, de := range des {
		info, err := de.Info()
		if err != nil {
			continue // removed meanwhile
		}
		full := filepath.Join(p, de.Name())
		e := Entry{Name: de.Name(), Path: full, Type: entryType(info.Mode()), Mtime: info.ModTime().Unix()}
		switch e.Type {
		case "file":
			e.Size = info.Size()
		case "symlink":
			// Size of the target only when the target is itself allowed
			// (never stat outside the roots).
			if target, err := filepath.EvalSymlinks(full); err == nil && rootOf(target, poolSet) != "" {
				if ti, err := os.Stat(target); err == nil {
					switch {
					case ti.Mode().IsRegular():
						e.Size = ti.Size()
						e.TargetType = "file"
					case ti.IsDir():
						e.TargetType = "dir"
					}
				}
			}
		}
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

// Open opens a regular file for download. The caller closes it.
func Open(raw string) (*os.File, fs.FileInfo, error) {
	p, err := Resolve(raw)
	if err != nil {
		return nil, nil, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil, nil, errNotFound
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, httperr.New(http.StatusBadRequest, "not a file")
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, errNotFound
		}
		return nil, nil, errForbidden
	}
	real, err := openedPath(f)
	if err != nil || !Allowed(real) {
		f.Close()
		return nil, nil, errForbidden
	}
	fi, err = f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, httperr.New(http.StatusBadRequest, "not a file")
	}
	return f, fi, nil
}

var contentTypes = map[string]string{
	".txt": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8", ".cfg": "text/plain; charset=utf-8",
	".conf": "text/plain; charset=utf-8", ".ini": "text/plain; charset=utf-8", ".md": "text/markdown; charset=utf-8",
	".csv": "text/csv; charset=utf-8", ".json": "application/json", ".xml": "application/xml", ".yml": "text/yaml; charset=utf-8",
	".yaml": "text/yaml; charset=utf-8", ".sh": "text/plain; charset=utf-8", ".plg": "application/xml",
	".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
	".pdf": "application/pdf", ".zip": "application/zip", ".gz": "application/gzip", ".tgz": "application/gzip",
	".tar": "application/x-tar", ".7z": "application/x-7z-compressed", ".rar": "application/vnd.rar",
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
	".heic": "image/heic", ".bmp": "image/bmp", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".tif": "image/tiff", ".tiff": "image/tiff",
	".mp4": "video/mp4", ".m4v": "video/x-m4v", ".mov": "video/quicktime", ".mkv": "video/x-matroska", ".webm": "video/webm",
	".avi": "video/x-msvideo", ".ts": "video/mp2t",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac", ".flac": "audio/flac", ".wav": "audio/wav", ".ogg": "audio/ogg", ".opus": "audio/opus",
	".srt": "text/plain; charset=utf-8", ".nfo": "text/plain; charset=utf-8",
}

// ContentType returns the media type for a file name by extension.
func ContentType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// ContentDisposition returns an attachment header for name (RFC 6266 /
// RFC 2231 encoding for non-ASCII names).
func ContentDisposition(name string) string {
	if v := mime.FormatMediaType("attachment", map[string]string{"filename": name}); v != "" {
		return v
	}
	return "attachment"
}
