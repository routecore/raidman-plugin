// Package emhttp talks to Unraid's emhttpd the same way the webGUI and the
// official Unraid API do.
//
// Reference implementations:
//   - unraid-api api/src/core/utils/clients/emcmd.ts: POST url-encoded
//     commands plus csrf_token (from /var/local/emhttp/var.ini) to
//     http://unix:/var/run/emhttpd.socket:/update; HTTP status >= 400 or a
//     non-empty response body means failure.
//   - unraid/webgui emhttp/plugins/dynamix/scripts/emcmd: identical protocol.
package emhttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	DefaultSocketPath = "/var/run/emhttpd.socket"
	DefaultVarIniPath = "/var/local/emhttp/var.ini"
)

// Client sends emcmd-style commands to emhttpd.
type Client struct {
	SocketPath string
	VarIniPath string
	Timeout    time.Duration
}

// Default is the client used by the services.
var Default = &Client{SocketPath: DefaultSocketPath, VarIniPath: DefaultVarIniPath, Timeout: 60 * time.Second}

// Cmd runs one emhttpd command. params are the form fields the webGUI would
// submit (e.g. {"cmdSpinupAll": "Apply"}); csrf_token is added automatically.
// It returns nil only when emhttpd accepted the command.
func (c *Client) Cmd(ctx context.Context, params url.Values) error {
	if _, err := os.Stat(c.SocketPath); err != nil {
		return fmt.Errorf("emhttpd socket unavailable (%s): %w", c.SocketPath, err)
	}
	token, err := ReadCsrfToken(c.VarIniPath)
	if err != nil {
		return fmt.Errorf("could not read csrf_token: %w", err)
	}
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("csrf_token", token)

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	socket := c.SocketPath
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/update", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("emhttpd request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("emhttpd request failed with status %d", resp.StatusCode)
	}
	if msg := strings.TrimSpace(string(body)); msg != "" {
		return fmt.Errorf("emhttpd: %s", msg)
	}
	return nil
}

// ReadCsrfToken returns csrf_token from var.ini.
func ReadCsrfToken(varIni string) (string, error) {
	vals, err := ReadIni(varIni)
	if err != nil {
		return "", err
	}
	tok := vals["csrf_token"]
	if tok == "" {
		return "", fmt.Errorf("csrf_token not present in %s", varIni)
	}
	return tok, nil
}

// ReadIni parses a flat key="value" ini file (section headers ignored).
func ReadIni(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == ';' || line[0] == '#' || line[0] == '[' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out, sc.Err()
}
