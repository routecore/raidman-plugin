// Package plugins lists, checks, updates and removes Unraid plugins through
// the stock plugin manager (/usr/local/sbin/plugin).
//
// Reference (unraid/webgui, dynamix.plugin.manager):
//   - Installed plugins: /var/log/plugins/*.plg (links to the flash copies in
//     /boot/config/plugins/*.plg, plus unRAIDServer.plg).
//   - "plugin checkall" downloads the latest .plg of every installed plugin to
//     /tmp/plugins/<basename of pluginURL>; the Plugins page compares that
//     version with the installed one.
//   - "plugin update <file>" installs /tmp/plugins/<file> over the installed
//     plugin; "plugin remove <file>" uninstalls it.
//
// Client-supplied names never reach argv: they are looked up in the parsed
// installed list and that entry's file name is passed.
package plugins

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/execx"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// Overridable in tests.
var (
	InstalledDir = "/var/log/plugins"
	BootDir      = "/boot/config/plugins"
	TmpDir       = "/tmp/plugins"
	PluginBinary = "/usr/local/sbin/plugin"
	// SelfUpdateLog receives the output of a detached RaidMan self-update.
	SelfUpdateLog = "/var/log/raidman-update.log"

	Run execx.Runner = execx.Run

	// StartDetached starts a command in its own session that outlives this
	// daemon (a RaidMan self-update stops the daemon while it runs).
	StartDetached = func(logFile, name string, args ...string) error {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		cmd := exec.Command(name, args...)
		cmd.Stdout, cmd.Stderr = f, f
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		go func() { _ = cmd.Wait() }()
		return nil
	}

	CheckAllTimeout = 5 * time.Minute
	CheckTimeout    = 2 * time.Minute
	RemoveTimeout   = 5 * time.Minute
)

// SelfName is this plugin's name (never removed; updated detached).
const SelfName = "raidman"

// maxPlgBytes bounds how much of a .plg is read (the PLUGIN tag is at the
// top; inline install scripts follow).
const maxPlgBytes = 4 << 20

// Plugin is one entry of GET /api/plugins.
type Plugin struct {
	Name            string `json:"name"`
	File            string `json:"file"`
	Version         string `json:"version"`
	Author          string `json:"author,omitempty"`
	PluginURL       string `json:"pluginURL,omitempty"`
	Support         string `json:"support,omitempty"`
	Icon            string `json:"icon,omitempty"`
	UpdateAvailable bool   `json:"updateAvailable"`
	LatestVersion   string `json:"latestVersion,omitempty"`
}

// OpResult is the update/remove response.
type OpResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// opMu serialises plugin manager operations (check, update, remove).
var opMu sync.Mutex

var errBusy = &httperr.Error{Status: http.StatusConflict, Msg: "another plugin operation is running"}

// ---- .plg parsing -----------------------------------------------------------

var (
	entityRe    = regexp.MustCompile(`<!ENTITY\s+([A-Za-z_][A-Za-z0-9_.-]*)\s+(?:"([^"]*)"|'([^']*)')\s*>`)
	entityRefRe = regexp.MustCompile(`&([A-Za-z_][A-Za-z0-9_.-]*);`)
	pluginTagRe = regexp.MustCompile(`<PLUGIN[\s>/]`)
)

// Entity expansion bounds: real .plg files declare about ten short entities.
const (
	maxPlgEntities    = 256
	maxEntityBytes    = 64 << 10
	maxExpansionBytes = 1 << 20
)

var errEntityExpansion = errors.New("entity expansion too large")

// ParsePLG returns the attributes of the <PLUGIN> element with the DOCTYPE's
// internal entities expanded (name="&name;" version="&version;" ...).
func ParsePLG(data []byte) (map[string]string, error) {
	loc := pluginTagRe.FindIndex(data)
	if loc == nil {
		return nil, errors.New("no PLUGIN element")
	}
	entities := map[string]string{}
	for _, m := range entityRe.FindAllSubmatch(data[:loc[0]], maxPlgEntities) {
		v := string(m[2])
		if len(m[3]) > 0 {
			v = string(m[3])
		}
		entities[string(m[1])] = v
	}
	// Expand nested references (pkgURL "&gitURL;/&version;"), bounded per
	// entity (checked while substituting, so an oversized result is never
	// built) and in total.
	total := 0
	for pass := 0; pass < 8; pass++ {
		changed := false
		for k, v := range entities {
			budget := maxEntityBytes - len(v)
			over := false
			nv := entityRefRe.ReplaceAllStringFunc(v, func(ref string) string {
				if over {
					return ref
				}
				name := ref[1 : len(ref)-1]
				r, ok := entities[name]
				if !ok || name == k {
					return ref
				}
				grow := len(r) - len(ref)
				if grow > budget {
					over = true
					return ref
				}
				budget -= grow
				return r
			})
			if over || nv == v {
				continue
			}
			total += len(nv) - len(v)
			if total > maxExpansionBytes {
				return nil, errEntityExpansion
			}
			entities[k] = nv
			changed = true
		}
		if !changed {
			break
		}
	}
	// Only the start tag is decoded; bound what its references expand to.
	tag := data[loc[0]:]
	tag = tag[:startTagEnd(tag)]
	expanded := 0
	for _, m := range entityRefRe.FindAllSubmatch(tag, -1) {
		expanded += len(entities[string(m[1])])
		if expanded > maxExpansionBytes {
			return nil, errEntityExpansion
		}
	}
	dec := xml.NewDecoder(bytes.NewReader(tag))
	dec.Strict = false
	dec.Entity = entities
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("parse PLUGIN element: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local != "PLUGIN" {
				return nil, errors.New("no PLUGIN element")
			}
			attrs := make(map[string]string, len(se.Attr))
			for _, a := range se.Attr {
				attrs[a.Name.Local] = strings.TrimSpace(a.Value)
			}
			return attrs, nil
		}
	}
}

// startTagEnd returns the length of the start tag at the beginning of b
// (through its closing '>', quotes respected), or len(b) when unterminated.
func startTagEnd(b []byte) int {
	var quote byte
	for i, c := range b {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i + 1
		}
	}
	return len(b)
}

func readPLG(p string) (map[string]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPlgBytes))
	if err != nil {
		return nil, err
	}
	return ParsePLG(data)
}

// ---- version compare ----------------------------------------------------------

type vtok struct {
	kind int // 0 number, 1 suffix (letters right after a digit), 2 pre-release (letters after a separator)
	num  string
	str  string
}

func tokenize(v string) []vtok {
	var out []vtok
	v = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")))
	i := 0
	prevDigit := false
	for i < len(v) {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n := strings.TrimLeft(v[i:j], "0")
			out = append(out, vtok{kind: 0, num: n})
			i, prevDigit = j, true
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			kind := 2
			if prevDigit {
				kind = 1
			}
			out = append(out, vtok{kind: kind, str: v[i:j]})
			i, prevDigit = j, false
		default:
			i, prevDigit = i+1, false
		}
	}
	return out
}

func cmpNum(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// rank orders token kinds at the same position: pre-release < suffix < number.
func rank(t vtok) int {
	switch t.kind {
	case 2:
		return 0
	case 1:
		return 1
	}
	return 2
}

// CompareVersions compares plugin versions segment-wise: numbers
// numerically, so 2026.11.18 < 2026.11.18a < 2026.11.19 and 7.2.0-rc.1 <
// 7.2.0 < 7.2.1. It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	ta, tb := tokenize(a), tokenize(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		if i >= len(ta) || i >= len(tb) {
			// The longer one is newer unless it continues with a pre-release tag.
			longer, sign := tb, -1
			if i >= len(tb) {
				longer, sign = ta, 1
			}
			if longer[i].kind == 2 {
				return -sign
			}
			return sign
		}
		x, y := ta[i], tb[i]
		if rank(x) != rank(y) {
			if rank(x) < rank(y) {
				return -1
			}
			return 1
		}
		var c int
		if x.kind == 0 {
			c = cmpNum(x.num, y.num)
		} else {
			c = strings.Compare(x.str, y.str)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

// ---- listing --------------------------------------------------------------------

func entryFrom(file string, attrs map[string]string) Plugin {
	name := attrs["name"]
	if name == "" {
		name = strings.TrimSuffix(file, ".plg")
	}
	return Plugin{
		Name:      name,
		File:      file,
		Version:   attrs["version"],
		Author:    attrs["author"],
		PluginURL: attrs["pluginURL"],
		Support:   attrs["support"],
		Icon:      attrs["icon"],
	}
}

// latestFile is where "plugin check" leaves the newest .plg of p.
func latestFiles(p Plugin) []string {
	var out []string
	if p.PluginURL != "" {
		if b := path.Base(p.PluginURL); strings.HasSuffix(b, ".plg") && b != p.File {
			out = append(out, filepath.Join(TmpDir, b))
		}
	}
	return append(out, filepath.Join(TmpDir, p.File))
}

// List parses the installed plugins (dedupe by file name; the installed copy
// in /var/log/plugins wins over the flash copy). Unreadable files are skipped.
func List() ([]Plugin, error) {
	seen := map[string]bool{}
	out := []Plugin{}
	readable := false
	for _, dir := range []string{InstalledDir, BootDir} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.plg"))
		if err != nil {
			continue
		}
		if _, err := os.Stat(dir); err == nil {
			readable = true
		}
		for _, m := range matches {
			file := filepath.Base(m)
			if seen[file] {
				continue
			}
			attrs, err := readPLG(m)
			if err != nil {
				continue
			}
			seen[file] = true
			p := entryFrom(file, attrs)
			for _, lf := range latestFiles(p) {
				la, err := readPLG(lf)
				if err != nil {
					continue
				}
				if lv := la["version"]; lv != "" {
					if CompareVersions(lv, p.Version) > 0 {
						p.UpdateAvailable = true
						p.LatestVersion = lv
					}
					break
				}
			}
			out = append(out, p)
		}
	}
	if !readable {
		return nil, &httperr.Error{Status: http.StatusNotImplemented, Msg: "plugin directory not found"}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].File < out[j].File
	})
	return out, nil
}

// find resolves a client-supplied plugin name or file name to an installed
// entry (exact match on name, file, or file without ".plg").
func find(name string) (Plugin, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Plugin{}, httperr.New(http.StatusBadRequest, "name missing")
	}
	list, err := List()
	if err != nil {
		return Plugin{}, err
	}
	for _, p := range list {
		if p.File == name || strings.TrimSuffix(p.File, ".plg") == name {
			return p, nil
		}
	}
	for _, p := range list {
		if p.Name == name {
			return p, nil
		}
	}
	return Plugin{}, httperr.New(http.StatusUnprocessableEntity, "plugin %q is not installed", name)
}

func isSelf(p Plugin) bool {
	return strings.EqualFold(p.Name, SelfName) || strings.EqualFold(p.File, SelfName+".plg")
}

func isOS(p Plugin) bool {
	return strings.EqualFold(strings.TrimSuffix(p.File, ".plg"), "unRAIDServer") || strings.EqualFold(p.Name, "unRAIDServer")
}

// RemoveRefusal returns why p must not be removed, or "" when it may be:
// the dynamix* system plugins, the OS (unRAIDServer) and RaidMan itself.
func RemoveRefusal(p Plugin) string {
	for _, s := range []string{p.Name, strings.TrimSuffix(p.File, ".plg")} {
		if strings.HasPrefix(strings.ToLower(s), "dynamix") {
			return "system plugins cannot be removed"
		}
	}
	if isOS(p) {
		return "the Unraid OS cannot be removed"
	}
	if isSelf(p) {
		return "RaidMan cannot remove itself"
	}
	return ""
}

func pluginBinary() error {
	if _, err := os.Stat(PluginBinary); err != nil {
		return &httperr.Error{Status: http.StatusNotImplemented, Msg: "plugin manager not found"}
	}
	return nil
}

func outputOf(res execx.Result) string {
	out := strings.TrimRight(string(res.Stdout), "\n")
	if e := strings.TrimRight(string(res.Stderr), "\n"); e != "" {
		if out != "" {
			out += "\n"
		}
		out += e
	}
	return out
}

// CheckAll runs "plugin checkall" and returns the refreshed list.
func CheckAll(ctx context.Context) ([]Plugin, error) {
	if err := pluginBinary(); err != nil {
		return nil, err
	}
	if !opMu.TryLock() {
		return nil, errBusy
	}
	defer opMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, CheckAllTimeout)
	defer cancel()
	_, err := Run(cctx, PluginBinary, "checkall")
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &httperr.Error{Status: http.StatusInternalServerError, Msg: "plugin check timed out"}
		}
		return nil, fmt.Errorf("plugin check failed: %w", err)
	}
	// A non-zero exit means some plugin could not be checked (its server is
	// down); the others were, so the list is still returned.
	return List()
}

// Update installs the newest version of an installed plugin. ctx bounds the
// whole operation (the API passes a daemon-scoped 10-minute context, so a
// client that disconnects does not kill an install halfway).
//
// RaidMan's own update stops this daemon, so it is started detached and
// reported as started (output in SelfUpdateLog). The OS (unRAIDServer.plg)
// is refused: OS updates go through the Unraid web UI.
func Update(ctx context.Context, name string) (OpResult, error) {
	if err := pluginBinary(); err != nil {
		return OpResult{}, err
	}
	p, err := find(name)
	if err != nil {
		return OpResult{}, err
	}
	if isOS(p) {
		return OpResult{}, httperr.New(http.StatusUnprocessableEntity, "Unraid OS updates are not supported here")
	}
	if !opMu.TryLock() {
		return OpResult{}, errBusy
	}
	defer opMu.Unlock()

	var out []string
	if _, err := os.Stat(filepath.Join(TmpDir, p.File)); err != nil {
		cctx, cancel := context.WithTimeout(ctx, CheckTimeout)
		res, err := Run(cctx, PluginBinary, "check", p.File)
		cancel()
		if err != nil {
			return OpResult{OK: false, Output: "plugin check failed: " + err.Error()}, nil
		}
		if o := outputOf(res); o != "" {
			out = append(out, o)
		}
	}

	if isSelf(p) {
		if err := StartDetached(SelfUpdateLog, PluginBinary, "update", p.File); err != nil {
			return OpResult{}, fmt.Errorf("could not start update: %w", err)
		}
		out = append(out, "plugin: updating "+p.File)
		return OpResult{OK: true, Output: strings.Join(out, "\n")}, nil
	}

	res, err := Run(ctx, PluginBinary, "update", p.File)
	if o := outputOf(res); o != "" {
		out = append(out, o)
	}
	if err != nil {
		msg := "plugin update failed: " + err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			msg = "plugin update timed out"
		}
		out = append(out, msg)
		return OpResult{OK: false, Output: strings.Join(out, "\n")}, nil
	}
	return OpResult{OK: res.ExitCode == 0, Output: strings.Join(out, "\n")}, nil
}

// Remove uninstalls an installed plugin ("plugin remove <file>"), refusing
// RemoveRefusal's list with 422.
func Remove(ctx context.Context, name string) (OpResult, error) {
	if err := pluginBinary(); err != nil {
		return OpResult{}, err
	}
	p, err := find(name)
	if err != nil {
		return OpResult{}, err
	}
	if why := RemoveRefusal(p); why != "" {
		return OpResult{}, httperr.New(http.StatusUnprocessableEntity, "%s", why)
	}
	if !opMu.TryLock() {
		return OpResult{}, errBusy
	}
	defer opMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, RemoveTimeout)
	defer cancel()
	res, err := Run(cctx, PluginBinary, "remove", p.File)
	out := outputOf(res)
	if err != nil {
		msg := "plugin remove failed: " + err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			msg = "plugin remove timed out"
		}
		if out != "" {
			out += "\n"
		}
		return OpResult{OK: false, Output: out + msg}, nil
	}
	return OpResult{OK: res.ExitCode == 0, Output: out}, nil
}
