package docker

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
)

func withMetaFixtures(t *testing.T) {
	t.Helper()
	oldT, oldN, oldX := TemplatesUserDir, NetworkIniPath, NginxIniPath
	t.Cleanup(func() { TemplatesUserDir, NetworkIniPath, NginxIniPath = oldT, oldN, oldX })
	TemplatesUserDir = "testdata/templates-user"
	NetworkIniPath = "testdata/network.ini"
	NginxIniPath = "testdata/nginx.ini"
}

func TestParseTemplate(t *testing.T) {
	f, err := os.Open("testdata/templates-user/my-plex.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tp, err := ParseTemplate(f)
	if err != nil {
		t.Fatal(err)
	}
	if tp.Name != "Plex" || tp.Shell != "bash" || tp.WebUI != "http://[IP]:[PORT:32400]/web" || tp.Project != "https://www.plex.tv/" {
		t.Fatalf("template = %+v", tp)
	}
	if tp.Ports[32400] != 32401 || len(tp.Ports) != 1 {
		t.Fatalf("ports = %v", tp.Ports)
	}
	if _, err := ParseTemplate(strings.NewReader("<nope")); err == nil {
		t.Fatal("broken xml must fail")
	}
}

func TestLoadUserTemplatesSkipsBroken(t *testing.T) {
	withMetaFixtures(t)
	ts := LoadUserTemplates()
	names := map[string]bool{}
	for _, x := range ts {
		names[x.Name] = true
	}
	if len(ts) != 3 || !names["Plex"] || !names["nextcloud"] || !names["weird"] {
		t.Fatalf("templates = %v", names)
	}
	// Second call comes from the cache and returns the same set.
	if len(LoadUserTemplates()) != 3 {
		t.Fatal("cache lost templates")
	}
}

func TestResolveWebUI(t *testing.T) {
	cases := []struct {
		in, ip         string
		pub, tmplPorts map[int]int
		want           string
	}{
		{"http://[IP]:[PORT:32400]/web", "192.168.1.150", map[int]int{32400: 32500}, nil, "http://192.168.1.150:32500/web"},
		{"http://[IP]:[PORT:32400]/web", "192.168.1.150", nil, map[int]int{32400: 32401}, "http://192.168.1.150:32401/web"},
		{"http://[IP]:[PORT:8080]/", "10.0.0.2", nil, nil, "http://10.0.0.2:8080/"},
		{"http://[IP]:[PORT:80]/", "", nil, nil, ""},
		{"http://[IP]:[PORT:80]/", "fd00::5", nil, nil, "http://[fd00::5]:80/"},
		{"http://my.custom.host:8080/", "", nil, nil, "http://my.custom.host:8080/"},
		{"", "192.168.1.150", nil, nil, ""},
	}
	for _, c := range cases {
		if got := ResolveWebUI(c.in, c.ip, c.pub, c.tmplPorts); got != c.want {
			t.Errorf("ResolveWebUI(%q, %q) = %q, want %q", c.in, c.ip, got, c.want)
		}
	}
}

func TestReadLanIP(t *testing.T) {
	withMetaFixtures(t)
	if ip := ReadLanIP(); ip != "192.168.1.150" {
		t.Fatalf("network.ini first interface: %q", ip)
	}
	NetworkIniPath = "testdata/missing.ini"
	if ip := ReadLanIP(); ip != "192.168.1.151" {
		t.Fatalf("nginx.ini fallback: %q", ip)
	}
	NginxIniPath = "testdata/missing.ini"
	if ip := ReadLanIP(); ip != "" {
		t.Fatalf("no source: %q", ip)
	}
}

func TestNormalizeShell(t *testing.T) {
	for in, want := range map[string]string{"sh": "sh", "bash": "bash", "/bin/bash": "bash", "/usr/bin/zsh": "zsh", "ash": "ash"} {
		if got, ok := NormalizeShell(in); !ok || got != want {
			t.Errorf("NormalizeShell(%q) = %q,%v", in, got, ok)
		}
	}
	for _, in := range []string{"", "python3", "bash -c id", "sh;id", "../bash", "-bash", "fish"} {
		if got, ok := NormalizeShell(in); ok {
			t.Errorf("NormalizeShell(%q) accepted as %q", in, got)
		}
	}
}

func TestBuildMeta(t *testing.T) {
	withMetaFixtures(t)
	containers := []container.Summary{
		{ // template matched by name, published port remapped
			ID: "aaa", Names: []string{"/plex"}, Image: "lscr.io/linuxserver/plex:latest",
			Labels: map[string]string{"net.unraid.docker.managed": "dockerman"},
			Ports:  []container.PortSummary{{PrivatePort: 32400, PublicPort: 32400, Type: "tcp"}},
		},
		{ // matched by repository; stopped -> template port mapping; label icon wins
			ID: "bbb", Names: []string{"/cloud"}, Image: "lscr.io/linuxserver/nextcloud",
			Labels: map[string]string{"net.unraid.docker.managed": "dockerman", "net.unraid.docker.icon": "https://label/icon.png"},
		},
		{ // compose project, label webui and shell, macvlan uses container IP
			ID: "ccc", Names: []string{"/web"}, Image: "nginx",
			Labels: map[string]string{
				"com.docker.compose.project": "stack",
				"net.unraid.docker.webui":    "http://[IP]:[PORT:80]/",
				"net.unraid.docker.shell":    "ash",
			},
			NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"br0": {IPAddress: netip.MustParseAddr("192.168.1.77")}}},
		},
		{ // shares another container's network: no WebUI
			ID: "ddd", Names: []string{"/vpnclient"}, Image: "someone/weird",
			Labels: map[string]string{"net.unraid.docker.webui": "http://[IP]:[PORT:80]/"},
		},
		{ // no template, no labels
			ID: "eee", Names: []string{"/bare"}, Image: "alpine",
		},
		{ // template shell not allowlisted -> sh; literal WebUI kept
			ID: "fff", Names: []string{"/weird"}, Image: "someone/weird",
			Labels: map[string]string{"net.unraid.docker.managed": "composeman"},
		},
		{ // running on macvlan br0: the template's 32400->32401 remap must not apply
			ID: "ggg", Names: []string{"/plex-br0"}, Image: "lscr.io/linuxserver/plex", State: "running",
			NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"br0": {IPAddress: netip.MustParseAddr("192.168.1.80")}}},
		},
		{ // running in host mode: container port, LAN IP
			ID: "hhh", Names: []string{"/plex-host"}, Image: "lscr.io/linuxserver/plex", State: "running",
		},
		{ // stopped on a user-defined bridge: template mapping predicts the port
			ID: "iii", Names: []string{"/plex-proxy"}, Image: "lscr.io/linuxserver/plex", State: "exited",
		},
	}
	containers[2].HostConfig.NetworkMode = "br0"
	containers[3].HostConfig.NetworkMode = "container:gluetun"
	containers[6].HostConfig.NetworkMode = "br0"
	containers[7].HostConfig.NetworkMode = "host"
	containers[8].HostConfig.NetworkMode = "proxynet"
	drivers := map[string]string{"br0": "macvlan", "bridge": "bridge", "host": "host", "proxynet": "bridge"}

	got := BuildMeta(containers, LoadUserTemplates(), ReadLanIP(), drivers)
	if len(got) != len(containers) {
		t.Fatalf("got %d", len(got))
	}
	s := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	check := func(i int, field, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s %s = %q, want %q", containers[i].Names[0], field, got, want)
		}
	}
	check(0, "webUi", s(got[0].WebUIURL), "http://192.168.1.150:32400/web")
	check(0, "shell", got[0].Shell, "bash")
	check(0, "managedBy", s(got[0].ManagedBy), "dockerman")
	check(0, "project", s(got[0].Project), "https://www.plex.tv/")
	check(0, "icon", s(got[0].IconURL), "https://raw.githubusercontent.com/linuxserver/docker-templates/master/linuxserver.io/img/plex-logo.png")

	check(1, "webUi", s(got[1].WebUIURL), "https://192.168.1.150:444/")
	check(1, "icon", s(got[1].IconURL), "https://label/icon.png")
	check(1, "shell", got[1].Shell, "zsh")
	check(1, "support", s(got[1].Support), "<nil>")

	check(2, "webUi", s(got[2].WebUIURL), "http://192.168.1.77:80/")
	check(2, "shell", got[2].Shell, "ash")
	check(2, "managedBy", s(got[2].ManagedBy), "compose")

	check(3, "webUi", s(got[3].WebUIURL), "<nil>")

	check(4, "webUi", s(got[4].WebUIURL), "<nil>")
	check(4, "icon", s(got[4].IconURL), "<nil>")
	check(4, "shell", got[4].Shell, "sh")
	check(4, "managedBy", s(got[4].ManagedBy), "<nil>")

	check(5, "webUi", s(got[5].WebUIURL), "http://my.custom.host:8080/")
	check(5, "shell", got[5].Shell, "sh")
	check(5, "managedBy", s(got[5].ManagedBy), "compose")

	check(6, "webUi", s(got[6].WebUIURL), "http://192.168.1.80:32400/web")
	check(7, "webUi", s(got[7].WebUIURL), "http://192.168.1.150:32400/web")
	check(8, "webUi", s(got[8].WebUIURL), "http://192.168.1.150:32401/web")
	if got[0].ID != "aaa" || got[0].Name != "plex" {
		t.Errorf("id/name = %q/%q", got[0].ID, got[0].Name)
	}
}

func TestMetaURLsMustBeHTTP(t *testing.T) {
	for in, want := range map[string]bool{
		"http://192.168.1.10:32400/web": true,
		"HTTPS://tower/icon.png":        true,
		"javascript:alert(1)":           false,
		"file:///etc/passwd":            false,
		"intent://x#Intent;end":         false,
		"//tower/x":                     false,
		"":                              false,
		"not a url":                     false,
	} {
		if got := httpURL(in) != nil; got != want {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}
