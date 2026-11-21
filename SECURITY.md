# Security Guide

## Overview
RaidMan authenticates every request with an Unraid API key, checks it against the key's roles and permissions with the same rules as the Unraid API, and writes an audit log of privileged actions.

## Authentication & Permissions
RaidMan reads the Unraid API key store (`/boot/config/plugins/dynamix.my.servers/keys`) and reloads it when keys are created, changed or deleted. Deleting or changing a key takes effect immediately, including for terminal, VNC and log sessions that are already open (they are closed within a few seconds).

Role expansion matches the Unraid API policy:
- `ADMIN`: everything.
- `VIEWER`: `READ_ANY` on every resource except `API_KEY`.
- `CONNECT`: `VIEWER` plus remote-access management.
- `GUEST`: only its own profile (`ME`), so it cannot use any RaidMan feature except the noVNC assets and VM icons.

### Permissions per feature
| Feature | Requirement |
|---|---|
| Container list, stats, logs, update status, WebUI/icon metadata | `DOCKER: READ_ANY` |
| Container start/stop/restart/pause, update check | `DOCKER: UPDATE_ANY` |
| Container console (`docker exec` shell) | `ADMIN` role |
| VM list, details, logs | `VMS: READ_ANY` |
| VM actions (including reset), autostart, VNC | `VMS: UPDATE_ANY` |
| VM serial console | `ADMIN` role |
| Array status, parity history, disk spin state, mover status | `ARRAY: READ_ANY` |
| Parity check start/pause/resume/cancel, spin up/down, mover start/stop | `ARRAY: UPDATE_ANY` |
| SMART data | `DISK: READ_ANY` |
| Plugin list | `CONFIG: READ_ANY` |
| Plugin update check, plugin update | `CONFIG: UPDATE_ANY` |
| Plugin removal | `ADMIN` role |
| NUT UPS status | `CONFIG: READ_ANY` |
| Memory breakdown | `INFO: READ_ANY` |
| File browser (list, download; read-only) | `ADMIN` role |
| Host terminal, shutdown, reboot | `ADMIN` role |
| Plugin version/feature discovery (`/api/health`), noVNC assets, VM icons | any valid key |

A shell in a container usually runs as root, and privileged containers or a mounted `docker.sock` reach the host; the VM serial console is a login prompt on the guest. Like the Unraid API, where `DOCKER: UPDATE_ANY` and `VMS: UPDATE_ANY` never include a shell, both require the `ADMIN` role.

Container environment variables (which often hold secrets) are removed from the container list unless the key has `DOCKER: UPDATE_ANY` and the request explicitly asks for them.

> [!IMPORTANT]
> **Terminal Access**: The host terminal, container console and VM serial console require the **ADMIN** role. The host terminal can also be disabled on the settings page.
> **VNC Access**: Requires `VMS: UPDATE_ANY`.

### File browser
The file browser is read-only and requires the `ADMIN` role. It covers `/mnt/user`, `/mnt/user0`, `/mnt/disk<N>`, `/mnt/cache`, the pools and `/boot`. Paths are checked before and after symlinks are resolved, and again on the opened file.

On the flash drive, these files and everything below these directories are always refused (`403`), whatever the key:
- `/boot/config/shadow`, `/boot/config/passwd`, `/boot/config/smbpasswd` (password hashes)
- `/boot/config/ssh`, `/boot/config/ssl`, `/boot/config/wireguard` (private keys)
- `/boot/config/plugins/dynamix.my.servers` (Unraid API key secrets)
- `/boot/config/plugins/raidman/settings.json` (this plugin's settings)

The check compares file identity (the resolved target and each of its parent directories), not names, because the flash drive is case-insensitive vfat: `/boot/CONFIG/Shadow` or a symlink to it is refused too. With **Host Terminal Access** disabled, an `ADMIN` key can still browse the shares and the rest of `/boot`, but never these files.

### Sessions
The in-app VNC viewer receives an opaque, random, HttpOnly session cookie. A session expires after one hour without use; each use extends it, and so does an open `vm-vnc` stream (re-checked every 5 seconds), but never beyond 12 hours after it was created (also the cookie's Max-Age). The API key itself is never stored in a plugin cookie, and sessions are re-checked against the key store on every request and while a stream is open.

Cookies are accepted only for the noVNC page and its `vm-vnc` stream, and only when the request's Origin (or Referer) is this server, including the port. Every other route and stream (host terminal, power, docker exec, ...) requires the `x-api-key` header, which a web page on another site or another port cannot send. Each key may hold at most 32 open streams and 16 VNC sessions; request bodies are limited to 1 MiB. If `settings.json` cannot be read at startup, RaidMan fails closed (all keys denied, host terminal off) until the settings are saved again.

## Network Security
- The daemon only listens on `127.0.0.1`; it is reached through Unraid's nginx at `/raidman/`.
- **Local Access**: Recommended. No extra config needed.
- **Remote Access**: Use a VPN (WireGuard/Tailscale).
- **Avoid**: Port forwarding or exposing directly to the internet. RaidMan does not rate-limit failed authentication attempts.

## Configuration & Settings
RaidMan provides a settings page in the Unraid web UI (`Settings -> Utilities -> RaidMan`) to control security features:

- **Host Terminal Access**: Enables or disables the ability to spawn a host shell via the plugin. Disabling it also closes open host terminal sessions.
- **API Key Restriction**: Only allow specific Unraid API keys to connect.
  - **No (Allow All)**: Any valid Unraid API key can connect (Default).
  - **Yes (Restrict)**: Only the selected API keys are allowed.

The settings page shows key names only and stores key **ids**, never key secrets.

## Architecture: raidman.page
The `raidman.page` file is a PHP script that integrates with Unraid's Dynamix web interface. It serves two purposes:
1. **Render the Settings UI**: Displays the configuration form in the Unraid settings tab.
2. **Enforce Configuration**: Saves preferences to `/boot/config/plugins/raidman/settings.json`, which the RaidMan binary reads to enforce security policies (e.g., disabling terminal access).

## Package integrity
- The plugin installs one versioned package, `raidman-<version>.tgz`, whose SHA-256 is pinned in `raidman.plg`; the install script checks it again and refuses a missing or empty checksum. The package contains noVNC (pinned version, verified against a hard-coded SHA-256 at build time), so nothing else is downloaded.
- Releases are built by GitHub Actions from a tag. The workflow runs with a read-only token except for the release job, and every action is pinned to a commit SHA.

## Best Practices
- Prefer a key with only the permissions you use over an `ADMIN` key.
- Rotate API keys regularly.
- Monitor logs in `/var/log/raidman.log` (`AUDIT` and `SECURITY` lines). Logs identify keys by name and id, never by any part of the secret. Unraid's logrotate keeps the log under 5 MB (one old copy, `raidman.log.1`), so it cannot fill the `/var/log` RAM disk.
- Report security issues to security@raidman.app.
