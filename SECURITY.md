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
| Container start/stop/restart/pause, container console, update check | `DOCKER: UPDATE_ANY` |
| VM list, details, logs | `VMS: READ_ANY` |
| VM actions, autostart, VNC, serial console | `VMS: UPDATE_ANY` |
| Array status, parity history, disk spin state, mover status | `ARRAY: READ_ANY` |
| Parity check start/pause/resume/cancel, spin up/down, mover start/stop | `ARRAY: UPDATE_ANY` |
| Host terminal, shutdown, reboot | `ADMIN` role |
| Plugin version/feature discovery (`/api/health`) | any valid key |

Container environment variables (which often hold secrets) are removed from the container list unless the key has `DOCKER: UPDATE_ANY` and the request explicitly asks for them.

> [!IMPORTANT]
> **Terminal Access**: Requires the **ADMIN** role and can be disabled on the settings page.
> **VNC Access**: Requires `VMS: UPDATE_ANY`.

### Sessions
The in-app VNC viewer receives an opaque, random, HttpOnly session cookie that expires after one hour. The API key itself is never stored in a plugin cookie, and sessions are re-checked against the key store on every request.

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

## Best Practices
- Prefer a key with only the permissions you use over an `ADMIN` key.
- Rotate API keys regularly.
- Monitor logs in `/var/log/raidman.log` (`AUDIT` and `SECURITY` lines). Logs identify keys by name and id, never by any part of the secret.
- Report security issues to security@raidman.app.
