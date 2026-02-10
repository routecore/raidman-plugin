# Security Guide

## Overview
RaidMan prioritizes security with API key validation, granular permissions, rate limiting, and audit logging.

## Authentication & Permissions
RaidMan uses Unraid's native permission system.

### Recommended Permissions
- **Docker**: `docker:read`, `docker:update`
- **VMs**: `vm:read`, `vm:update`
- **Array**: `array:read`

> [!IMPORTANT]
> **Terminal Access**: Requires the **ADMIN** role.
> **VNC Access**: Requires `vm:update` permission.

## Network Security
- **Local Access**: Recommended. No extra config needed.
- **Remote Access**: Use a VPN (WireGuard/Tailscale).
- **Avoid**: Port forwarding or exposing directly to the internet.

## Configuration & Settings
RaidMan provides a settings page in the Unraid web UI (`Settings -> Utilities -> RaidMan`) to control security features:

- **Host Terminal Access**: Enables or disables the ability to spawn a host shell via the plugin.
- **API Key Restriction**: Secure the plugin by only allowing specific Unraid API keys to connect.
  - **No (Allow All)**: Any valid Unraid API key can connect (Default).
  - **Yes (Restrict)**: Only the selected API keys are allowed to establish a connection.

## Architecture: raidman.page
The `raidman.page` file is a PHP script that integrates with Unraid's Dynamix web interface. It serves two purposes:
1. **Render the Settings UI**: Displays the configuration form in the Unraid settings tab.
2. **Enforce Configuration**: Saves preferences to `/boot/config/plugins/raidman/settings.json`, which the RaidMan binary reads to enforce security policies (e.g., disabling terminal access).

## Best Practices
- Rotate API keys regularly.
- Monitor logs at `/var/log/raidman.log`.
- Report security issues to security@raidman.app.
