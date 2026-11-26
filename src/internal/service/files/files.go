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
//
// Inside /boot, credentials and private keys are refused (see deniedBoot):
// the resolved target and each of its ancestors are compared by file
// identity (os.SameFile), never by name, because the flash drive is vfat
// (case-insensitive, 8.3 aliases), so /boot/CONFIG/Shadow is the same file
// as /boot/config/shadow.
package files

import (
	"container/heap"
	"context"
	"errors"
	"io"
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
	// MaxScan is a hard stop on how many names one listing reads from a
	// directory; beyond it the listing is marked truncated and incomplete.
	MaxScan = 200000
	// readChunk is how many entries are read from a directory at a time.
	readChunk = 1024
	// evalSymlinks resolves client paths, symlink entries and the
	// configured bases (a hook for tests).
	evalSymlinks = resolveSymlinks
	// lstat is the lookup resolveSymlinks makes for each component.
	lstat = os.Lstat
)

// deniedBoot lists files and directories (relative to BootDir) that are never
// listed or served, nor anything below them: password hashes, SSH/SSL/
// WireGuard private keys, the Wi-Fi password (wireless.cfg), Samba's machine
// secrets (secrets.tdb), rclone remotes and their tokens (config/rclone, and
// the rclone plugin's config), the Unraid API key secrets and the plugin's
// own settings. The license key files (config/*.key) are added by
// loadDenied, since their names vary (Basic.key, Pro.key, Starter.key ...).
var deniedBoot = []string{
	"config/shadow",
	"config/passwd",
	"config/smbpasswd",
	"config/ssh",
	"config/ssl",
	"config/wireguard",
	"config/wireless.cfg",
	"config/secrets.tdb",
	"config/rclone",
	"config/plugins/rclone/.rclone.conf",
	"config/plugins/dynamix.my.servers",
	"config/plugins/raidman/settings.json",
}

// deniedBootKeyDir holds the license key files (*.key, any case: the flash is
// vfat, so PRO.KEY is as valid as Pro.key), relative to BootDir.
const deniedBootKeyDir = "config"

// Path length limits (Linux NAME_MAX and PATH_MAX without the NUL). A longer
// path is refused before anything touches the filesystem: Unraid's user
// share filesystem (shfs, FUSE) crashes on an over-long name ("strcpy_share_path
// ... path too long") and takes /mnt/user down until the array is restarted.
//
// Under /mnt/user and /mnt/user0 the limit is tighter (maxUserPathLen):
// shfs serves each path from a disk or pool by rewriting its /mnt/user
// prefix to /mnt/disk<N> or /mnt/<pool>, so the path it builds internally is
// longer than the one it was given. Pool names are up to 64 bytes here
// (poolNameRe), so the rewritten prefix ("/mnt/" + name) is at most 69 bytes;
// leaving a whole name (255 bytes) of headroom keeps every rewritten path
// below PATH_MAX with room to spare, and no real path comes near 3840 bytes.
const (
	maxNameLen     = 255
	maxPathLen     = 4095
	maxUserPathLen = maxPathLen - maxNameLen
	// maxSymlinks is the kernel's limit on links followed in one lookup
	// (MAXSYMLINKS); more answers ELOOP.
	maxSymlinks = 40
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
	errSensitive = &httperr.Error{Status: http.StatusForbidden, Msg: "path not allowed: sensitive file"}
	// 422, not 404: the app reads a plugin 404 as "route missing (old plugin)".
	errNotFound = &httperr.Error{Status: http.StatusUnprocessableEntity, Msg: "path not found"}
	errTooLong  = &httperr.Error{Status: http.StatusBadRequest, Msg: "path too long"}
)

// fsError turns a filesystem error into a client error. The raw error is
// never sent: it carries the full path (which may be kilobytes of client
// input) and a Go operation name. Only the errno text is kept as the reason
// (e.g. "transport endpoint is not connected" when shfs is down).
func fsError(err error) error {
	var he *httperr.Error
	switch {
	case errors.As(err, &he): // already a client error (errTooLong, ...)
		return err
	case errors.Is(err, fs.ErrNotExist):
		return errNotFound
	case errors.Is(err, fs.ErrPermission):
		return errForbidden
	case errors.Is(err, syscall.ENAMETOOLONG):
		return errTooLong
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}
	reason := "I/O error"
	var errno syscall.Errno
	if errors.As(err, &errno) {
		reason = errno.Error()
	}
	return &httperr.Error{Status: http.StatusInternalServerError, Msg: "cannot access path: " + reason}
}

// checkLength refuses a path, or one of its components, longer than the
// kernel allows (see maxNameLen).
func checkLength(raw string) error {
	return checkLengthMax(raw, maxPathLen)
}

// checkLengthMax is checkLength with max as the limit on the whole path.
func checkLengthMax(raw string, max int) error {
	if len(raw) > max {
		return errTooLong
	}
	for _, seg := range strings.Split(raw, "/") {
		if len(seg) > maxNameLen {
			return errTooLong
		}
	}
	return nil
}

// userShareRoots returns /mnt/user and /mnt/user0 under every form of
// MntDir (as configured and symlink-resolved), where maxUserPathLen applies.
func userShareRoots() []string {
	mnt := []string{filepath.Clean(MntDir)}
	if r, err := walkSymlinks(MntDir, nil); err == nil && r != mnt[0] {
		mnt = append(mnt, r)
	}
	out := make([]string, 0, 2*len(mnt))
	for _, m := range mnt {
		out = append(out, m+"/user", m+"/user0")
	}
	return out
}

// checkPathLength applies checkLength to p, with the tighter user-share
// limit when p is inside one of userRoots.
func checkPathLength(p string, userRoots []string) error {
	for _, r := range userRoots {
		if under(p, r) {
			return checkLengthMax(p, maxUserPathLen)
		}
	}
	return checkLength(p)
}

// resolveSymlinks returns the absolute path p with every symlink resolved,
// like filepath.EvalSymlinks, except that no path longer than the limits
// (see maxNameLen and maxUserPathLen) is ever looked up: symlink targets
// come from the disk, not the client, so a link whose target holds an
// over-long name would otherwise hand that name to shfs.
func resolveSymlinks(p string) (string, error) {
	return walkSymlinks(p, userShareRoots())
}

// walkSymlinks resolves p one component at a time. Every path is checked
// (checkPathLength) before it is passed to Lstat, and every link target and
// the path it expands to are checked before anything below them is looked
// up; a violation answers errTooLong. More than maxSymlinks links answer
// ELOOP, as the kernel would.
func walkSymlinks(p string, userRoots []string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", &fs.PathError{Op: "resolve", Path: p, Err: syscall.EINVAL}
	}
	if err := checkPathLength(filepath.Clean(p), userRoots); err != nil {
		return "", err
	}
	dest := "/"
	rest := p
	links := 0
	for rest != "" {
		var name string
		name, rest, _ = strings.Cut(rest, "/")
		switch name {
		case "", ".":
			continue
		case "..":
			// dest has no symlinks left, so its lexical parent is the
			// real one.
			dest = filepath.Dir(dest)
			continue
		}
		next := filepath.Join(dest, name)
		if err := checkPathLength(next, userRoots); err != nil {
			return "", err
		}
		fi, err := lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			if !fi.IsDir() && rest != "" {
				return "", &fs.PathError{Op: "lstat", Path: next, Err: syscall.ENOTDIR}
			}
			dest = next
			continue
		}
		if links++; links > maxSymlinks {
			return "", &fs.PathError{Op: "lstat", Path: next, Err: syscall.ELOOP}
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if err := checkLength(target); err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			dest = "/"
		}
		if rest != "" {
			target += "/" + rest
		}
		rest = target
		// The whole path the link expands to, before any of it is
		// looked up.
		if err := checkPathLength(dest+"/"+rest, userRoots); err != nil {
			return "", err
		}
	}
	return dest, nil
}

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
	// Protected marks a denied /boot path (or a symlink to one): it is listed
	// but cannot be opened or downloaded (403 "sensitive file").
	Protected bool `json:"protected,omitempty"`
}

// Listing is the GET /api/files/list response.
//
// Entries are one page of the sorted directory. Truncated is set when more
// entries exist after this page or the directory was not read to the end;
// Next is the offset of the next page when one can be requested. Total is
// the number of entries read (a lower bound when Incomplete is set, i.e.
// the read stopped at MaxScan).
type Listing struct {
	Path       string  `json:"path"`
	Parent     *string `json:"parent"`
	Entries    []Entry `json:"entries"`
	Truncated  bool    `json:"truncated,omitempty"`
	Total      int     `json:"total"`
	Offset     int     `json:"offset,omitempty"`
	Next       *int    `json:"next,omitempty"`
	Incomplete bool    `json:"incomplete,omitempty"`
}

// ListOptions selects a page of a listing. Limit 0 means MaxEntries.
type ListOptions struct {
	Offset int
	Limit  int
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
	if r, err := evalSymlinks(dir); err == nil && r != out[0] {
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

// denySet is the identity of the denied paths that exist right now. It is
// built per request and never cached: vfat inode numbers are only stable
// while the inode stays in memory.
type denySet []fs.FileInfo

func loadDenied() denySet {
	var d denySet
	for _, rel := range deniedBoot {
		if fi, err := os.Stat(filepath.Join(BootDir, rel)); err == nil {
			d = append(d, fi)
		}
	}
	// License key files: matched by suffix ignoring case, then by identity
	// like every other entry.
	keyDir := filepath.Join(BootDir, deniedBootKeyDir)
	if des, err := os.ReadDir(keyDir); err == nil {
		for _, de := range des {
			if n := de.Name(); strings.HasSuffix(strings.ToLower(n), ".key") {
				if fi, err := os.Stat(filepath.Join(keyDir, n)); err == nil {
					d = append(d, fi)
				}
			}
		}
	}
	return d
}

func (d denySet) match(fi fs.FileInfo) bool {
	for _, x := range d {
		if os.SameFile(x, fi) {
			return true
		}
	}
	return false
}

// covers reports whether the resolved path p, or any directory above it, is
// a denied path. self, when set, is p's own FileInfo from an open descriptor.
func (d denySet) covers(p string, self fs.FileInfo) bool {
	if len(d) == 0 {
		return false
	}
	if self != nil && d.match(self) {
		return true
	}
	for q := p; ; {
		if fi, err := os.Stat(q); err == nil && d.match(fi) {
			return true
		}
		up := filepath.Dir(q)
		if up == q {
			return false
		}
		q = up
	}
}

// Resolve validates a client path and returns its canonical form (all
// symlinks resolved, see resolveSymlinks). 400: empty, relative, NUL or too
// long (the path, a link target or a link's expansion); 403: ".." segments,
// outside the roots (before or after resolving) or a denied /boot path; 422:
// missing; 500: any other filesystem error (ELOOP, EIO ...) with its reason.
// Errors never echo the path.
func Resolve(raw string) (string, error) {
	if raw == "" {
		return "", httperr.New(http.StatusBadRequest, "path missing")
	}
	if strings.ContainsRune(raw, 0) || !strings.HasPrefix(raw, "/") {
		return "", httperr.New(http.StatusBadRequest, "invalid path")
	}
	// Before any filesystem call (see maxNameLen).
	if err := checkLength(raw); err != nil {
		return "", err
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
	resolved, err := evalSymlinks(clean)
	if err != nil {
		return "", fsError(err)
	}
	if rootOf(resolved, poolSet) == "" {
		return "", errForbidden
	}
	if loadDenied().covers(resolved, nil) {
		return "", errSensitive
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

// listItem is a directory entry with its precomputed sort key.
type listItem struct {
	dir   bool
	lower string
	de    fs.DirEntry
}

// less orders directories first, then by name case-insensitively, then by
// exact name.
func (a *listItem) less(b *listItem) bool {
	if a.dir != b.dir {
		return a.dir
	}
	if a.lower != b.lower {
		return a.lower < b.lower
	}
	return a.de.Name() < b.de.Name()
}

// topItems is a max-heap (by less) keeping the n smallest items seen.
type topItems []*listItem

func (h topItems) Len() int           { return len(h) }
func (h topItems) Less(i, j int) bool { return h[j].less(h[i]) }
func (h topItems) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *topItems) Push(x any)        { *h = append(*h, x.(*listItem)) }
func (h *topItems) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// List returns the first page of a directory (see ListContext).
func List(raw string) (Listing, error) {
	return ListContext(context.Background(), raw, ListOptions{})
}

// ListContext returns one page of a directory's entries: directories first,
// then by name (case-insensitive). The directory is read in chunks (ctx is
// checked between them) and at most MaxScan names are read; only the
// offset+limit smallest entries are kept in memory while reading.
func ListContext(ctx context.Context, raw string, opt ListOptions) (Listing, error) {
	limit := opt.Limit
	if limit <= 0 || limit > MaxEntries {
		limit = MaxEntries
	}
	offset := min(max(opt.Offset, 0), MaxScan)
	p, err := Resolve(raw)
	if err != nil {
		return Listing{}, err
	}
	if fi, err := os.Stat(p); err != nil {
		return Listing{}, fsError(err)
	} else if !fi.IsDir() {
		return Listing{}, httperr.New(http.StatusBadRequest, "not a directory")
	}
	// O_DIRECTORY: a path swapped for a FIFO after the Stat fails instead of
	// blocking in open.
	d, err := os.OpenFile(p, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// ENOENT 422, EACCES 403, anything else (ELOOP: the directory was
		// swapped for a symlink; ENOTDIR; EIO ...) 500 with the reason.
		return Listing{}, fsError(err)
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return Listing{}, fsError(err)
	}
	if !fi.IsDir() {
		return Listing{}, httperr.New(http.StatusBadRequest, "not a directory")
	}
	// Re-check through the descriptor (a component swapped after Resolve).
	real, err := openedPath(d)
	if err != nil {
		return Listing{}, fsError(err)
	}
	if !Allowed(real) || loadDenied().covers(real, fi) {
		return Listing{}, errForbidden
	}

	keep := offset + limit
	h := make(topItems, 0, min(keep, readChunk))
	total, incomplete := 0, false
	for {
		if err := ctx.Err(); err != nil {
			return Listing{}, err
		}
		des, err := d.ReadDir(readChunk)
		for _, de := range des {
			if total >= MaxScan {
				incomplete = true
				break
			}
			total++
			it := &listItem{dir: de.IsDir(), lower: strings.ToLower(de.Name()), de: de}
			if len(h) < keep {
				heap.Push(&h, it)
			} else if it.less(h[0]) {
				h[0] = it
				heap.Fix(&h, 0)
			}
		}
		if incomplete || errors.Is(err, io.EOF) || (err == nil && len(des) == 0) {
			break
		}
		if err != nil {
			if total == 0 {
				return Listing{}, fsError(err)
			}
			incomplete = true // keep what was read
			break
		}
	}
	items := []*listItem(h)
	sort.Slice(items, func(i, j int) bool { return items[i].less(items[j]) })
	page := items[min(offset, len(items)):]

	out := Listing{Path: p, Entries: make([]Entry, 0, len(page)), Total: total, Offset: offset, Incomplete: incomplete}
	if end := offset + len(page); end < total {
		out.Truncated = true
		out.Next = &end
	}
	if incomplete {
		out.Truncated = true
	}
	poolSet := pools()
	if root := rootOf(p, poolSet); root != "" && p != root {
		parent := filepath.Dir(p)
		out.Parent = &parent
	}
	var denied denySet
	deniedLoaded := false
	inBoot := false
	for _, b := range bases(BootDir) {
		inBoot = inBoot || under(p, b)
	}
	userRoots := userShareRoots()
	for _, it := range page {
		de := it.de
		full := filepath.Join(p, de.Name())
		if checkPathLength(full, userRoots) != nil {
			// Too long to look up (de.Info is an lstat; see
			// maxUserPathLen): listed by name and type only.
			out.Entries = append(out.Entries, Entry{Name: de.Name(), Path: full, Type: entryType(de.Type())})
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue // removed meanwhile
		}
		e := Entry{Name: de.Name(), Path: full, Type: entryType(info.Mode()), Mtime: info.ModTime().Unix()}
		if inBoot && e.Type != "symlink" {
			if !deniedLoaded {
				denied, deniedLoaded = loadDenied(), true
			}
			e.Protected = denied.match(info)
		}
		switch e.Type {
		case "file":
			e.Size = info.Size()
		case "symlink":
			// Resolving the link looks up each component of its target,
			// wherever it points (the lengths are checked first, see
			// resolveSymlinks); a target that cannot be resolved, or whose
			// path is too long, is left unresolved (no targetType). Only a
			// target inside the roots is stat'ed, and a denied one only
			// marks the entry protected.
			if target, err := evalSymlinks(full); err == nil && rootOf(target, poolSet) != "" {
				if !deniedLoaded {
					denied, deniedLoaded = loadDenied(), true
				}
				ti, err := os.Stat(target)
				if err == nil && denied.covers(target, ti) {
					e.Protected = true
				} else if err == nil {
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
		return nil, nil, fsError(err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, httperr.New(http.StatusBadRequest, "not a file")
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// As in ListContext: only EACCES is 403, ELOOP and the rest 500.
		return nil, nil, fsError(err)
	}
	real, err := openedPath(f)
	if err != nil {
		f.Close()
		return nil, nil, fsError(err)
	}
	if !Allowed(real) {
		f.Close()
		return nil, nil, errForbidden
	}
	fi, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fsError(err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, httperr.New(http.StatusBadRequest, "not a file")
	}
	// The opened file itself (descriptor identity) and its directories.
	if loadDenied().covers(real, fi) {
		f.Close()
		return nil, nil, errSensitive
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
