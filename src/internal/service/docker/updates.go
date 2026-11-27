package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Paths used by Unraid's Docker manager (dockerMan). Overridable in tests.
var (
	// UpdateStatusPath is written by the webGUI (DockerClient.php
	// DockerUpdate::reloadUpdateStatus) and read by the official API
	// (docker-php.service.ts readCachedUpdateStatus).
	UpdateStatusPath = "/var/lib/docker/unraid-update-status.json"
	// DockerUpdateScript is dynamix.docker.manager/scripts/dockerupdate. With
	// "check nonotify" it runs DockerTemplates->getAllInfo(true), which
	// re-reads local digests and fetches remote manifests (no image pull),
	// and skips the notifications the scheduled "check" run sends.
	DockerUpdateScript = "/usr/local/emhttp/plugins/dynamix.docker.manager/scripts/dockerupdate"
	// UpdateCheckTimeout bounds one update check (one registry round trip
	// per container; offline registries can take a while to time out).
	UpdateCheckTimeout = 15 * time.Minute
)

// UpdateEntry is one record of unraid-update-status.json. The webGUI writes
// local/remote as null when a digest cannot be resolved and status as
// "true" (up to date), "false" (update available) or "undef" (unknown).
type UpdateEntry struct {
	Local  *string `json:"local"`
	Remote *string `json:"remote"`
	Status *string `json:"status"`
}

// ContainerUpdate is one element of GET /api/docker/updates.
type ContainerUpdate struct {
	Name            string  `json:"name"`
	Image           string  `json:"image"`
	UpdateAvailable *bool   `json:"updateAvailable"`
	LocalDigest     *string `json:"localDigest"`
	RemoteDigest    *string `json:"remoteDigest"`
	CheckedAt       *string `json:"checkedAt"`
}

// ParseUpdateStatus decodes unraid-update-status.json per entry so one
// malformed record does not discard the whole file (same tolerance as the
// official API).
func ParseUpdateStatus(data []byte) (map[string]UpdateEntry, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]UpdateEntry, len(raw))
	for image, msg := range raw {
		var e UpdateEntry
		if err := json.Unmarshal(msg, &e); err != nil {
			continue
		}
		out[image] = e
	}
	return out, nil
}

// EnsureImageTag mirrors the webGUI's DockerUtil::ensureImageTag, which
// builds the keys of unraid-update-status.json: images without a '/' get a
// "library/" prefix and images without a tag get ":latest". A tag is only
// recognised after the last '/', so registry ports stay intact.
func EnsureImageTag(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	if strings.HasPrefix(image, "sha256:") {
		return image
	}
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at] // digest references carry no tag
	}
	if !strings.Contains(image, "/") {
		image = "library/" + image
	}
	slash := strings.LastIndex(image, "/")
	repo, last := image[:slash+1], image[slash+1:]
	name, tag, _ := strings.Cut(last, ":")
	tag = strings.ReplaceAll(tag, ":", "")
	if tag == "" {
		tag = "latest"
	}
	return repo + name + ":" + tag
}

// lookupUpdate finds the status record for an image the way both the
// webGUI (ensureImageTag) and the official API (append ":latest") key it.
func lookupUpdate(status map[string]UpdateEntry, image string) (UpdateEntry, bool) {
	candidates := []string{EnsureImageTag(image), image}
	if !strings.Contains(image[strings.LastIndex(image, "/")+1:], ":") {
		candidates = append(candidates, image+":latest")
	}
	for _, c := range candidates {
		if e, ok := status[c]; ok {
			return e, true
		}
	}
	return UpdateEntry{}, false
}

func normDigest(d *string) *string {
	if d == nil {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(*d))
	if v == "" || v == "undef" || v == "null" {
		return nil
	}
	return &v
}

// UpdateAvailable evaluates one record. Digests are compared first; the
// status string is the fallback. Note: in the webGUI status "true" means
// local == remote (UP TO DATE, DockerClient.php reloadUpdateStatus) and the
// dockerupdate script notifies on "false".
func UpdateAvailable(e UpdateEntry) *bool {
	l, r := normDigest(e.Local), normDigest(e.Remote)
	if l != nil && r != nil {
		v := *l != *r
		return &v
	}
	if e.Status != nil {
		switch strings.ToLower(strings.TrimSpace(*e.Status)) {
		case "true":
			v := false
			return &v
		case "false":
			v := true
			return &v
		}
	}
	return nil
}

// BuildUpdates combines a container list with the parsed status file.
// checkedAt is the status file's modification time (nil if unknown).
func BuildUpdates(containers []container.Summary, status map[string]UpdateEntry, checkedAt *time.Time) []ContainerUpdate {
	var ts *string
	if checkedAt != nil && !checkedAt.IsZero() {
		s := checkedAt.UTC().Format(time.RFC3339)
		ts = &s
	}
	out := make([]ContainerUpdate, 0, len(containers))
	for _, c := range containers {
		u := ContainerUpdate{Name: primaryName(c.Names), Image: c.Image}
		if e, ok := lookupUpdate(status, c.Image); ok {
			u.UpdateAvailable = UpdateAvailable(e)
			u.LocalDigest = normDigest(e.Local)
			u.RemoteDigest = normDigest(e.Remote)
			u.CheckedAt = ts
		}
		out = append(out, u)
	}
	return out
}

// GetUpdates reads Unraid's cached update status. It never contacts a
// registry and never pulls: the data is whatever the last dockerMan check
// (scheduled, webGUI, or TriggerUpdateCheck) wrote.
func GetUpdates(ctx context.Context) ([]ContainerUpdate, error) {
	cli, err := getDockerClient()
	if err != nil {
		return nil, err
	}
	listed, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	containers := listed.Items
	status := map[string]UpdateEntry{}
	var checkedAt *time.Time
	if data, err := os.ReadFile(UpdateStatusPath); err == nil {
		if st, err := os.Stat(UpdateStatusPath); err == nil {
			m := st.ModTime()
			checkedAt = &m
		}
		if parsed, err := ParseUpdateStatus(data); err == nil {
			status = parsed
		} else {
			log.Printf("docker updates: cannot parse %s: %v", UpdateStatusPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read update status: %w", err)
	}
	return BuildUpdates(containers, status, checkedAt), nil
}

func primaryName(names []string) string {
	for _, n := range names {
		n = strings.TrimPrefix(n, "/")
		if n != "" && !strings.Contains(n, "/") {
			return n
		}
	}
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	return ""
}

// ---- update check -----------------------------------------------------------

// ErrCheckUnavailable means the dockerMan update script is not installed.
var ErrCheckUnavailable = errors.New("docker update check is not available on this server")

var (
	checkMu      sync.Mutex
	checkRunning bool
)

// UpdateCheckRunning reports whether a check started by this daemon is
// still running.
func UpdateCheckRunning() bool {
	checkMu.Lock()
	defer checkMu.Unlock()
	return checkRunning
}

// startCommand is overridable in tests (never exec the real script there).
var startCommand = func(cmd *exec.Cmd) error { return cmd.Start() }

// TriggerUpdateCheck starts Unraid's own update check in the background and
// returns once the process has started. alreadyRunning is true when a check
// is still in progress (no second one is started). parent bounds the
// check's lifetime (the daemon's base context), not the HTTP request.
func TriggerUpdateCheck(parent context.Context) (alreadyRunning bool, err error) {
	if _, err := os.Stat(DockerUpdateScript); err != nil {
		return false, ErrCheckUnavailable
	}
	checkMu.Lock()
	defer checkMu.Unlock()
	if checkRunning {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(parent, UpdateCheckTimeout)
	cmd := exec.CommandContext(ctx, DockerUpdateScript, "check", "nonotify")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	if err := startCommand(cmd); err != nil {
		cancel()
		return false, fmt.Errorf("start update check: %w", err)
	}
	checkRunning = true
	go func() {
		defer cancel()
		err := cmd.Wait()
		checkMu.Lock()
		checkRunning = false
		checkMu.Unlock()
		if err != nil {
			log.Printf("docker update check ended with error: %v", err)
		} else {
			log.Printf("docker update check finished")
		}
	}()
	return false, nil
}
