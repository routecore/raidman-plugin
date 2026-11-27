package docker

import (
	"bufio"
	"context"
	"encoding/xml"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Paths overridable in tests.
var (
	// TemplatesUserDir holds the user's dockerMan templates (my-<name>.xml).
	TemplatesUserDir = "/boot/config/plugins/dockerMan/templates-user"
	// NetworkIniPath / NginxIniPath are emhttp state files used to find the
	// server's LAN IP (same sources as the official API's getLanIp()).
	NetworkIniPath = "/var/local/emhttp/network.ini"
	NginxIniPath   = "/var/local/emhttp/nginx.ini"
)

// Container labels written by Unraid's Docker manager (DockerClient.php
// getDockerContainers) and by the Compose Manager plugin.
const (
	labelManaged = "net.unraid.docker.managed"
	labelWebUI   = "net.unraid.docker.webui"
	labelIcon    = "net.unraid.docker.icon"
	labelShell   = "net.unraid.docker.shell"
	labelCompose = "com.docker.compose.project"
)

// ExecShells is the allowlist for the docker exec shell (contract §4).
var ExecShells = []string{"sh", "bash", "ash", "zsh"}

// NormalizeShell maps a template/label/query shell value ("bash",
// "/bin/bash") onto the allowlist. ok is false for anything else.
func NormalizeShell(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	base := s
	if strings.HasPrefix(s, "/") {
		base = filepath.Base(s)
	}
	for _, a := range ExecShells {
		if base == a {
			return a, true
		}
	}
	return "", false
}

// Template is the subset of a dockerMan template the plugin uses.
type Template struct {
	Path       string
	Name       string
	Repository string
	WebUI      string
	Icon       string
	Shell      string
	Support    string
	Project    string
	// Ports maps container port -> host port from <Config Type="Port">.
	Ports map[int]int
}

type xmlTemplate struct {
	XMLName    xml.Name `xml:"Container"`
	Name       string   `xml:"Name"`
	Repository string   `xml:"Repository"`
	WebUI      string   `xml:"WebUI"`
	Icon       string   `xml:"Icon"`
	Shell      string   `xml:"Shell"`
	Support    string   `xml:"Support"`
	Project    string   `xml:"Project"`
	Configs    []struct {
		Type   string `xml:"Type,attr"`
		Target string `xml:"Target,attr"`
		Mode   string `xml:"Mode,attr"`
		Value  string `xml:",chardata"`
	} `xml:"Config"`
}

// ParseTemplate parses a dockerMan template. It is lenient like the PHP
// DOMDocument loader: unknown entities and non-UTF-8 encoding declarations
// do not fail the parse.
func ParseTemplate(r io.Reader) (*Template, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var x xmlTemplate
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	t := &Template{
		Name:       strings.TrimSpace(x.Name),
		Repository: strings.TrimSpace(x.Repository),
		WebUI:      strings.TrimSpace(x.WebUI),
		Icon:       strings.TrimSpace(x.Icon),
		Shell:      strings.TrimSpace(x.Shell),
		Support:    strings.TrimSpace(x.Support),
		Project:    strings.TrimSpace(x.Project),
		Ports:      map[int]int{},
	}
	for _, c := range x.Configs {
		if !strings.EqualFold(c.Type, "Port") {
			continue
		}
		target, err1 := strconv.Atoi(strings.TrimSpace(c.Target))
		host, err2 := strconv.Atoi(strings.TrimSpace(c.Value))
		if err1 == nil && err2 == nil {
			t.Ports[target] = host
		}
	}
	return t, nil
}

type cachedTemplate struct {
	mtime time.Time
	size  int64
	tmpl  *Template
}

var (
	tmplMu    sync.Mutex
	tmplCache = map[string]cachedTemplate{}
)

// LoadUserTemplates reads every *.xml in TemplatesUserDir. Parsed templates
// are cached by path, mtime and size, so repeated calls only stat the flash
// drive.
func LoadUserTemplates() []*Template {
	entries, err := os.ReadDir(TemplatesUserDir)
	if err != nil {
		return nil
	}
	tmplMu.Lock()
	defer tmplMu.Unlock()
	seen := map[string]bool{}
	var out []*Template
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".xml") || strings.HasPrefix(name, ".") {
			continue
		}
		p := filepath.Join(TemplatesUserDir, name)
		seen[p] = true
		info, err := e.Info()
		if err != nil {
			continue
		}
		if c, ok := tmplCache[p]; ok && c.mtime.Equal(info.ModTime()) && c.size == info.Size() {
			if c.tmpl != nil {
				out = append(out, c.tmpl)
			}
			continue
		}
		var t *Template
		if f, err := os.Open(p); err == nil {
			t, err = ParseTemplate(io.LimitReader(f, 4<<20))
			f.Close()
			if err != nil {
				t = nil
			} else {
				t.Path = p
			}
		}
		tmplCache[p] = cachedTemplate{mtime: info.ModTime(), size: info.Size(), tmpl: t}
		if t != nil {
			out = append(out, t)
		}
	}
	for p := range tmplCache {
		if !seen[p] {
			delete(tmplCache, p)
		}
	}
	return out
}

// normalizeRepo strips digest and tag (tag only after the last '/') and
// lower-cases, as the official API's template scanner does.
func normalizeRepo(repo string) string {
	repo, _, _ = strings.Cut(repo, "@")
	if c, s := strings.LastIndex(repo, ":"), strings.LastIndex(repo, "/"); c > s {
		repo = repo[:c]
	}
	return strings.ToLower(repo)
}

// MatchTemplate finds a container's template: by <Name> first (case
// insensitive), then by repository (official API docker-template-scanner).
func MatchTemplate(name, image string, templates []*Template) *Template {
	n := strings.ToLower(strings.TrimPrefix(name, "/"))
	if n != "" {
		for _, t := range templates {
			if t.Name != "" && strings.ToLower(strings.TrimPrefix(t.Name, "/")) == n {
				return t
			}
		}
	}
	img := normalizeRepo(image)
	if img != "" {
		for _, t := range templates {
			if t.Repository != "" && normalizeRepo(t.Repository) == img {
				return t
			}
		}
	}
	return nil
}

var (
	ipPlaceholder   = regexp.MustCompile(`\[IP\]`)
	portPlaceholder = regexp.MustCompile(`\[PORT:(\d+)\]`)
)

// ResolveWebUI substitutes the dockerMan placeholders [IP] and [PORT:n]:
// [IP] becomes ip; [PORT:n] becomes the host port published for container
// port n (running containers), else the template's mapping, else n. It
// returns "" when the URL needs an IP that is unknown.
func ResolveWebUI(webui, ip string, published map[int]int, templatePorts map[int]int) string {
	webui = strings.TrimSpace(webui)
	if webui == "" {
		return ""
	}
	if ipPlaceholder.MatchString(webui) {
		if ip == "" {
			return ""
		}
		host := ip
		if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
			host = "[" + ip + "]" // IPv6 literal in a URL
		}
		webui = ipPlaceholder.ReplaceAllLiteralString(webui, host)
	}
	webui = portPlaceholder.ReplaceAllStringFunc(webui, func(m string) string {
		n, err := strconv.Atoi(portPlaceholder.FindStringSubmatch(m)[1])
		if err != nil {
			return m
		}
		if p, ok := published[n]; ok && p > 0 {
			return strconv.Itoa(p)
		}
		if p, ok := templatePorts[n]; ok && p > 0 {
			return strconv.Itoa(p)
		}
		return strconv.Itoa(n)
	})
	return webui
}

// ReadLanIP returns the server's LAN IPv4: the first interface's IPADDR:0
// in network.ini, else NGINX_LANIP from nginx.ini (official API getLanIp()).
func ReadLanIP() string {
	if ip := firstSectionValue(NetworkIniPath, "IPADDR:0"); ip != "" {
		return ip
	}
	return firstSectionValue(NginxIniPath, "NGINX_LANIP")
}

// firstSectionValue returns key's value from the first section that has it
// (section order preserved, unlike a map-based ini parse).
func firstSectionValue(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		if v = strings.Trim(strings.TrimSpace(v), `"`); v != "" {
			return v
		}
	}
	return ""
}

// ContainerMeta is one element of GET /api/docker/meta.
type ContainerMeta struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	WebUIURL  *string `json:"webUiUrl"`
	IconURL   *string `json:"iconUrl"`
	Shell     string  `json:"shell"`
	Support   *string `json:"support"`
	Project   *string `json:"project"`
	ManagedBy *string `json:"managedBy"`
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// httpURL returns s when it is an absolute http(s) URL, else nil. Template
// and label values are opened by the app; anything else (javascript:, file:,
// intent:, ...) is dropped.
func httpURL(s string) *string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil
	}
	if sc := strings.ToLower(u.Scheme); sc != "http" && sc != "https" {
		return nil
	}
	return &s
}

// BuildMeta derives metadata for containers. lanIP replaces [IP] for host
// and bridge networking; macvlan/ipvlan containers use their own address
// (as the webGUI does); containers sharing another container's network get
// no WebUI URL.
func BuildMeta(containers []container.Summary, templates []*Template, lanIP string, drivers map[string]string) []ContainerMeta {
	out := make([]ContainerMeta, 0, len(containers))
	for _, c := range containers {
		name := primaryName(c.Names)
		labels := c.Labels
		t := MatchTemplate(name, c.Image, templates)
		var tp map[int]int
		var tWebUI, tIcon, tShell, tSupport, tProject string
		if t != nil {
			tp, tWebUI, tIcon, tShell, tSupport, tProject = t.Ports, t.WebUI, t.Icon, t.Shell, t.Support, t.Project
		}

		m := ContainerMeta{ID: c.ID, Name: name, Shell: "sh"}

		webui := labels[labelWebUI]
		if webui == "" {
			webui = tWebUI
		}
		mode := c.HostConfig.NetworkMode
		if !strings.HasPrefix(mode, "container:") && webui != "" {
			ip := lanIP
			if d := drivers[mode]; d == "macvlan" || d == "ipvlan" {
				ip = ""
				if c.NetworkSettings != nil {
					if n := c.NetworkSettings.Networks[mode]; n != nil && n.IPAddress.IsValid() {
						ip = n.IPAddress.String()
					}
				}
			}
			published := map[int]int{}
			for _, p := range c.Ports {
				if p.PublicPort > 0 {
					if _, dup := published[int(p.PrivatePort)]; !dup {
						published[int(p.PrivatePort)] = int(p.PublicPort)
					}
				}
			}
			// The template's host-port mapping only predicts the URL of a
			// stopped container on a NAT'd bridge. A running container's
			// published ports are authoritative, and host/macvlan/ipvlan
			// containers are reached on the container port itself (webGUI
			// getControlURL keeps n unless a NAT'd port matches).
			natted := mode == "" || mode == "default" || mode == "bridge" || drivers[mode] == "bridge"
			fallback := tp
			if c.State == "running" || !natted {
				fallback = nil
			}
			m.WebUIURL = httpURL(ResolveWebUI(webui, ip, published, fallback))
		}

		icon := labels[labelIcon]
		if icon == "" {
			icon = tIcon
		}
		m.IconURL = httpURL(icon)

		for _, s := range []string{labels[labelShell], tShell} {
			if v, ok := NormalizeShell(s); ok {
				m.Shell = v
				break
			}
		}
		m.Support = strPtr(tSupport)
		m.Project = strPtr(tProject)

		switch mgr := labels[labelManaged]; {
		case mgr == "dockerman":
			m.ManagedBy = strPtr("dockerman")
		case mgr == "composeman" || labels[labelCompose] != "":
			m.ManagedBy = strPtr("compose")
		}
		out = append(out, m)
	}
	return out
}

// GetMeta lists containers (no inspect, no size) and derives metadata.
func GetMeta(ctx context.Context) ([]ContainerMeta, error) {
	cli, err := getDockerClient()
	if err != nil {
		return nil, err
	}
	listed, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	containers := listed.Items
	drivers := map[string]string{}
	if nets, err := cli.NetworkList(ctx, client.NetworkListOptions{}); err == nil {
		for _, n := range nets.Items {
			drivers[n.Name] = n.Driver
		}
	}
	return BuildMeta(containers, LoadUserTemplates(), ReadLanIP(), drivers), nil
}
