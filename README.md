# RaidMan Unraid Plugin

Remote management plugin for Unraid servers, providing real-time monitoring and control for the RaidMan mobile app.

> [!WARNING]
> Please read the [Security Guide](SECURITY.md) before installation.

## Requirements
- Unraid **7.0 or later**.
- The **Unraid API**: built into Unraid 7.2+; on 7.0/7.1 install the Unraid Connect plugin.

## Features
- 🔐 **Unraid API keys**: the plugin uses the same keys, roles and permissions as the official Unraid API, with audit logging.
- 🖥️ **Terminal & VNC**: access to the host, containers and VMs.
- 📊 **Real-time Monitoring**: Docker, VM, and Array stats.
- 🐳 **Management**: control over Docker containers, VMs, parity checks, disk spin state and the mover.
- 🔄 **Container updates**: update status from Unraid's own checker (never pulls images), WebUI links, icons and shells from your templates.

## Installation
1. Install via Unraid Community Applications (or use URL: `https://raw.githubusercontent.com/routecore/raidman-plugin/main/raidman.plg`)
2. Go to **Settings → Management Access → API Keys**
3. Create a key. Either give it a role (`ADMIN` for everything, `VIEWER` for read-only access) or grant permissions per resource:
   - `DOCKER`: `READ_ANY` (containers, stats, logs), `UPDATE_ANY` (start/stop, container console)
   - `VMS`: `READ_ANY` (VM list, details, logs), `UPDATE_ANY` (start/stop, autostart, VNC, serial console)
   - `ARRAY`: `READ_ANY` (array status, parity history, disk spin state, mover status), `UPDATE_ANY` (parity check, spin up/down, mover)

> [!NOTE]
> The host terminal and shutdown/reboot require the **ADMIN** role. VNC requires `VMS: UPDATE_ANY`.
> Permissions are checked exactly like the Unraid API does: a `GUEST` key can only read its own profile, `UPDATE_ANY` does not imply `READ_ANY`, and `*_OWN` does not imply `*_ANY`.

## Service
- `/etc/rc.d/rc.raidman {start|stop|restart|status}`
- The daemon listens on `127.0.0.1:9876`; nginx proxies `/raidman/` to it.

## Monitoring & Troubleshooting
- **Logs**: `tail -f /var/log/raidman.log` (rotated at 5 MB on service start)
- **Security Events**: `grep -E "AUDIT|SECURITY" /var/log/raidman.log`
- Keys that cannot be parsed are logged with `[AUTH]`.

## API (protocol 2)

All routes are served under `/raidman/` by nginx (proxied to `127.0.0.1:9876`) and require the
`x-api-key` header. Protocol-1 routes keep their request/response shapes and plain-text errors.
Protocol-2 routes answer JSON; every error (including 401/403/405) is `{"error": "<message>"}`.

Status codes: `401` missing/invalid key, `403` key lacks the permission, `405` wrong method,
`400` invalid request, `404` unknown disk/container, `409` wrong state (e.g. pausing a parity check
that is not running), `500` the underlying Unraid command failed, `501` feature not available on this server.
A success response is only sent after Unraid accepted the command.

### Discovery

| Route | Permission | Response |
|---|---|---|
| `GET /api/health` | any valid key | `{"version":"2026.11.18","protocol":2,"features":[...],"unraid":"7.2.0","hostTerminal":true}` |

`features`: `docker.updates`, `docker.meta`, `disks.state`, `disks.spin`, `mover`, `parity.v2`, `power`,
`terminal.resize`, `vm.reset`, `vm.ips`, `vm.hostdevs`, `plugins.list`, `plugins.ops`, `disks.smart`, `files`,
`mem.breakdown`, `ups.nut`. `unraid` is `null` if unknown. `hostTerminal` is
`false` when the host terminal is disabled in the plugin settings (the `host` stream then refuses). A 404 means either a protocol-1 plugin or no plugin at all
(both answer 404 under `/raidman/`); clients tell them apart with the protocol-1 `/connect` probe.

### Protocol-2 routes

| Route | Permission | Request | Response |
|---|---|---|---|
| `GET /api/docker/updates` | `DOCKER:READ_ANY` | | `[{"name","image","updateAvailable":true\|false\|null,"localDigest","remoteDigest","checkedAt"}]` |
| `POST /api/docker/updates/check` | `DOCKER:UPDATE_ANY` | | `{"started":true}` (+ `"alreadyRunning":true` if a check is in progress) |
| `GET /api/docker/meta` | `DOCKER:READ_ANY` | | `[{"id","name","webUiUrl","iconUrl","shell","support","project","managedBy"}]` |
| `GET /api/disks/state` | `ARRAY:READ_ANY` | | `[{"name","device","type","spundown","temp","status","rotational"}]` |
| `POST /api/disks/spin` | `ARRAY:UPDATE_ANY` | `{"disk":"disk1"\|"all","action":"up"\|"down"}` | `{"ok":true}` |
| `GET /api/mover/status` | `ARRAY:READ_ANY` | | `{"running":false}` |
| `POST /api/mover/action` | `ARRAY:UPDATE_ANY` | `{"action":"start"\|"stop"}` | `{"ok":true,"running":bool}` |
| `POST /api/parity/action` | `ARRAY:UPDATE_ANY` | `{"action":"start"\|"pause"\|"resume"\|"cancel","correct":false}` | `{"ok":true}` |
| `GET /api/plugins` | `CONFIG:READ_ANY` | | `{"plugins":[{"name","file","version","author?","pluginURL?","support?","icon?","updateAvailable","latestVersion?"}]}` |
| `POST /api/plugins/check` | `CONFIG:UPDATE_ANY` | | same as `GET /api/plugins`, after `plugin checkall` |
| `POST /api/plugins/update` | `CONFIG:UPDATE_ANY` | `{"name":"ca.plg"}` | `{"ok":bool,"output":"..."}` (+ `"message"` = output when `ok` is false) |
| `POST /api/plugins/remove` | `ADMIN` | `{"name":"ca.plg"}` | `{"ok":bool,"output":"..."}` (+ `"message"` when `ok` is false) |
| `GET /api/disks/smart?device=sdb` | `ARRAY:READ_ANY` | | `{"device","standby","passed","temperature","powerOnHours","attributes":[{"id","name","value","worst","thresh","raw","failing"}]}` |
| `GET /api/files/list?path=/mnt/user` | `ADMIN` | | `{"path","parent","entries":[{"name","path","type":"dir"\|"file"\|"symlink","size","mtime","targetType"?}],"truncated"?}` |
| `GET /api/files/download?path=...` | `ADMIN` | | raw bytes (Range supported), `Content-Disposition: attachment` |
| `GET /api/system/memory` | `INFO:READ_ANY` | | `{"totalBytes","usedBytes","cachedBytes","zfsArcBytes","vmBytes","dockerBytes"}` |
| `GET /api/ups/nut` | `CONFIG:READ_ANY` | | `{"available":bool,"devices":[{"name","vars":{"ups.status":"OL",...}}]}` |
| `POST /api/system/action` | `ADMIN` | `{"action":"shutdown"\|"reboot","safeMode":bool?}` | `{"success":true}` (protocol-1 shape) |

Details:
- **Feature-wave errors** use 422 for a missing entity (plugin, device, path) and for refused plugin
  operations, 403 for paths outside the allowed roots, 409 while another plugin operation runs and 501 for a missing host tool (`smartctl`, `plugin`).
  They never answer 404 (reserved for "route missing") or 502–504 (read as "daemon down").
- **Plugins** are parsed from `/var/log/plugins/*.plg` then `/boot/config/plugins/*.plg` (DOCTYPE entities
  expanded); `updateAvailable` compares with the `.plg` that `plugin check` leaves in `/tmp/plugins`. Names
  are matched against the installed list, so client input never reaches argv. Update has a 10 min limit,
  checks first when no newer `.plg` was downloaded, refuses the OS (`unRAIDServer`) and runs RaidMan's own
  update detached (output in `/var/log/raidman-update.log`). Remove refuses `dynamix*`, `unRAIDServer` and
  RaidMan itself. One plugin operation at a time.
- **SMART** runs `smartctl -n standby -j -H -A /dev/<device>` (device `^(sd[a-z]{1,2}|nvme\d+n\d+)$`); a
  sleeping disk is never woken (`standby: true`, no attributes). NVMe health-log counters are returned as
  attributes numbered from 1.
- **Files** are read-only. Paths are canonicalised (`..` refused, symlinks resolved) and must stay under
  `/mnt/user`, `/mnt/user0`, `/mnt/disk<N>`, `/mnt/cache`, `/mnt/<pool>` (pools from `/boot/config/pools/*.cfg`)
  or `/boot`; the opened descriptor is checked again. Directories first, at most 5000 entries; `mtime` is
  Unix seconds.
- **Memory**: `/proc/meminfo` (used = total − available, cached = buffers + cache + reclaimable slab), ZFS ARC
  from `/proc/spl/kstat/zfs/arcstats`, VMs = resident memory of the qemu processes, Docker = the `docker`
  cgroup minus inactive file cache. Unknown values are `null`.
- **NUT** uses `upsc -l` / `upsc <ups>` against the local upsd plus the systems on `upsmon.conf` `MONITOR`
  lines (remote NUT servers). `available` is false when no UPS answered.
- **Docker updates** come from `/var/lib/docker/unraid-update-status.json`, the file Unraid's Docker
  manager writes. Digests are compared first; otherwise the webGUI status is used (`"true"` = up to date,
  `"false"` = update available, `"undef"` = unknown → `null`). `checkedAt` is the file's modification time
  (RFC 3339), `null` when the image has no record. Reading never contacts a registry.
  `GET` adds the header `X-Raidman-Update-Check: running` while a check started by the plugin runs.
- **Update check** runs `dynamix.docker.manager/scripts/dockerupdate check nonotify` in the background
  (manifest digests only, no image pull, no notifications), at most one at a time, 15 min limit.
  Poll `GET /api/docker/updates` until the `X-Raidman-Update-Check` header is gone; `checkedAt` is not a
  completion signal (Unraid rewrites the file after each container).
- **Docker meta** uses the container list only (no inspect, no size calculation). Values come from the
  `net.unraid.docker.{webui,icon,shell,managed}` labels, then from the matching template in
  `/boot/config/plugins/dockerMan/templates-user` (matched by `<Name>`, then by repository).
  In `webUiUrl`, `[IP]` is the server's LAN IP (`network.ini`, then `nginx.ini`), or the container's own IP
  on macvlan/ipvlan networks; `[PORT:n]` is the published host port for container port `n`, else the
  template mapping, else `n`. Containers using another container's network get `null`. `shell` is always
  one of `sh`, `bash`, `ash`, `zsh` (default `sh`), ready for the `shell=` parameter. `managedBy` is
  `dockerman`, `compose` or `null`.
- **Disk state** is parsed from `/var/local/emhttp/disks.ini` (and `devs.ini` for unassigned devices,
  `type:"Unassigned"`). It never touches a disk, so polling it never wakes a spun-down drive. `type` is the
  emhttp slot type (`Parity`, `Data`, `Cache`, `Flash`, `Boot` on Unraid 7.3 internal boot, ...). `temp`
  is `null` when emhttp reports `*` (spun down) or nothing.
- **Spin** sends the webGUI's own emhttpd commands (`cmdSpinupAll`/`cmdSpindownAll`, or
  `cmdSpinup`/`cmdSpindown=<name>`).
- **Mover**: `start` posts `cmdStartMover` to emhttpd like the webGUI's Move button (409 if the array is not
  started, user shares are off, or the mover already runs); `stop` runs `/usr/local/sbin/mover stop` and
  checks that the mover is gone. Status comes from `shareMoverActive` in `var.ini` and `/var/run/mover.pid`.
- **Parity** uses the webGUI/Unraid API form fields: `cmdCheck` (+ `optionCorrect=correct` when
  `correct` is true), `cmdCheckPause`, `cmdCheckResume` (continues where it paused), `cmdCheckCancel`.
  The state is checked first (`409` when it does not apply).
- **Power**: shutdown/reboot run `/sbin/poweroff` / `/sbin/reboot` without `-f`, which hand over to init so
  Unraid's shutdown script stops services and the array cleanly (the same path as the webGUI buttons).
  `safeMode` (optional) sets or clears `/boot/unraidsafemode`; omitted leaves it unchanged.

### VM additions (protocol-1 routes, new optional fields)

| Route | Permission | Change |
|---|---|---|
| `POST /api/vm/action` | `VMS:UPDATE_ANY` | new action `reset` (feature `vm.reset`); unknown actions → `400`; `reset` on a VM that is not running → `409` |
| `GET /api/vm/info`, `GET /api/vms` | `VMS:READ_ANY` | `interfaces[].ipAddresses` (feature `vm.ips`), `hostdevs[]` (feature `vm.hostdevs`), `detailedState` `blocked` / `shutdown` |

- **reset** is a hard reset (`virDomainReset`, like the reset button; the guest is not asked). Allowed while
  the VM is running, idle (`blocked`) or paused. Only if the hypervisor reports reset as unsupported and the VM
  is running/idle and persistent, the plugin force-stops and starts it instead. A `crashed` VM is force-stopped
  and started again (persistent VMs only, like the official API's `resetVm`); any other state → `409`. Errors stay
  plain text (protocol-1 route); success is `{"success":true}`.
- **IPs per NIC**: one `DomainInterfaceAddresses` query per source for the whole VM, in the order guest agent
  (only when the agent channel is connected), DHCP lease, host ARP table; a source is asked only while some NIC
  still has no address. Addresses are matched to each NIC by MAC; loopback, link-local, unspecified and multicast
  addresses are dropped; IPv4 comes first. `ipAddresses` is `[]` when nothing is known (always `[]` for a shut-off
  or other inactive VM; a paused VM is asked via lease/ARP only); `ipAddress` is its first entry or `""`. Older plugins sent the first IPv4 of any NIC (from
  the host ARP table) on every NIC.
- **hostdevs**: PCI and USB passthrough devices from `<devices><hostdev mode="subsystem">`:
  `[{"type":"pci"|"usb","kind":"gpu"|"audio"|"usb"|null,"name":string|null,"vendor":string|null,"address":string}]`.
  `address` is the host PCI address (`0000:01:00.0`), the USB `vendor:product` ids (`046d:c52b`), or
  `bus.device` (`001.004`) for a USB device given by bus address. `kind` comes from the PCI class in sysfs
  (`0x03xxxx` → `gpu`, `0x0403xx` → `audio`, `0x0c03xx` USB controller → `usb`; every USB device is `usb`).
  Names come from `/sys/bus/pci/devices/<address>/{vendor,device}` and `pci.ids` / `usb.ids`
  (`/usr/share/hwdata` or `/usr/share/misc`); nothing is executed. `hostdevs` is `[]` without passthrough
  devices and `null` if the domain XML could not be read.
- **States** (`detailedState`): `running`, `blocked` (libvirt idle), `paused`, `shutdown` (shutting down),
  `shutoff`, `crashed`, `pmsuspended`, `unknown`.

### WebSocket streams (`/connect?type=...`)

| Type | Permission | Parameters |
|---|---|---|
| `array-status` | `ARRAY:READ_ANY` | |
| `docker-stats` | `DOCKER:READ_ANY` | `container` (optional) |
| `docker-log` | `DOCKER:READ_ANY` | `container` |
| `docker` (exec) | `DOCKER:UPDATE_ANY` | `container`, `shell` (optional: `sh` default, `bash`, `ash`, `zsh`; anything else → error frame) |
| `vm-log` | `VMS:READ_ANY` | `vm` |
| `vm` (serial) / `vm-vnc` | `VMS:UPDATE_ANY` | `vm` (name or UUID) |
| `host` | `ADMIN` (and enabled in settings) | |

Container ids may be raw Docker ids, names, or Unraid API PrefixedIDs (`<serverId>:<id>`).

**Terminal resize** (`host`, `docker`, `vm`): send a *text* frame that is exactly either
`\x1b[8;<rows>;<cols>t` or the JSON object `{"type":"resize","cols":N,"rows":M}` (1–1000). Any other frame
is terminal input. Older plugins write such frames to the terminal, so only send them when `/api/health`
lists `terminal.resize`.

Sockets accept messages up to 64 KiB (4 MiB for VNC), ping every 30 s, and are closed with code `1008`
when the key is deleted or loses the permission.

## Support
- **Issues**: [GitHub Issues](https://github.com/routecore/raidman-plugin/issues)
- **Security**: security@raidman.app

## License
Distributed under the MIT License. See `LICENSE` for more information.
