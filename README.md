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
   - `DOCKER`: `READ_ANY` (containers, stats, logs), `UPDATE_ANY` (start/stop, update check)
   - `VMS`: `READ_ANY` (VM list, details, logs), `UPDATE_ANY` (start/stop, autostart, VNC)
   - `ARRAY`: `READ_ANY` (array status, parity history, disk spin state, mover status), `UPDATE_ANY` (parity check, spin up/down, mover)
   - `DISK`: `READ_ANY` (SMART data)
   - `CONFIG`: `READ_ANY` (plugin list, NUT UPS status), `UPDATE_ANY` (plugin update check and update)
   - `INFO`: `READ_ANY` (memory breakdown)

> [!NOTE]
> The host terminal, container console (`docker exec`), VM serial console, file browser, plugin removal and shutdown/reboot require the **ADMIN** role. VNC requires `VMS: UPDATE_ANY`.
> The file browser never serves password hashes, private keys or API key secrets from `/boot` (see the [Security Guide](SECURITY.md#file-browser)).
> Permissions are checked exactly like the Unraid API does: a `GUEST` key can only read its own profile, `UPDATE_ANY` does not imply `READ_ANY`, and `*_OWN` does not imply `*_ANY`.

## Service
- `/etc/rc.d/rc.raidman {start|stop|restart|status}`
- The daemon listens on `127.0.0.1:9876`; nginx proxies `/raidman/` to it.
- `start` runs the daemon under a small supervisor that restarts it after a crash (backoff 2 s doubling to 60 s,
  reset after a minute of uptime; logged as `[SUPERVISOR]`). `stop` ends both, and a clean exit is not restarted.
  `start` reports success only once the daemon itself listens on the port. The daemon runs in `/` with `HOME=/root`.
- If nginx rejects its configuration when RaidMan installs, the daemon adds its include once `nginx -t` passes
  (checked every minute and whenever `locations.conf` changes).

## Monitoring & Troubleshooting
- **Logs**: `tail -f /var/log/raidman.log` (kept under 5 MB by Unraid's logrotate via `/etc/logrotate.d/raidman`; one old copy in `raidman.log.1`)
- **Security Events**: `grep -E "AUDIT|SECURITY" /var/log/raidman.log`
- Keys that cannot be parsed are logged with `[AUTH]`.

## API (protocol 2)

All routes are served under `/raidman/` by nginx (proxied to `127.0.0.1:9876`) and require the
`x-api-key` header. Protocol-1 routes keep their request/response shapes and plain-text errors, except the
`422` `not_found` answer for an unknown container or VM, which is JSON.
Protocol-2 routes answer JSON; every error (including 401/403/405) is `{"error": "<message>", "code"?: "<code>"}`.

Status codes: `401` missing/invalid key, `403` key lacks the permission, `405` wrong method,
`400` invalid request, `422` with `"code":"not_found"` unknown disk/container/VM (a `404` only means the route
does not exist, i.e. an older plugin), `409` wrong state (e.g. pausing a parity check
that is not running, pausing a paused container, starting a running VM), `500` the underlying Unraid command
failed, `501` feature not available on this server (with `"code":"smart_unsupported"` for a disk that cannot
report SMART).
A success response is only sent after Unraid accepted the command.

### Discovery

| Route | Permission | Response |
|---|---|---|
| `GET /api/health` | any valid key | `{"version":"2026.11.18","protocol":2,"features":[...],"unraid":"7.2.0","hostTerminal":true}` |

`features`: `docker.updates`, `docker.meta`, `disks.state`, `disks.spin`, `mover`, `parity.v2`, `power`,
`terminal.resize`, `vm.reset`, `vm.ips`, `vm.hostdevs`, `plugins.list`, `plugins.ops`, `disks.smart`,
`disks.smart.disk` (SMART requires `DISK:READ_ANY`; older plugins required `ARRAY:READ_ANY`), `files`, `mem.breakdown`, `ups.nut`, `array.encryption`. `unraid` is `null` if unknown. `hostTerminal` is
`false` when the host terminal is disabled in the plugin settings (the `host` stream then refuses). A 404 means either a protocol-1 plugin or no plugin at all
(both answer 404 under `/raidman/`); clients tell them apart with the protocol-1 `/connect` probe.

### Protocol-2 routes

| Route | Permission | Request | Response |
|---|---|---|---|
| `GET /api/docker/updates` | `DOCKER:READ_ANY` | | `[{"name","image","updateAvailable":true\|false\|null,"localDigest","remoteDigest","checkedAt"}]` |
| `POST /api/docker/updates/check` | `DOCKER:UPDATE_ANY` | | `{"started":true}` (+ `"alreadyRunning":true` if a check is in progress) |
| `GET /api/docker/meta` | `DOCKER:READ_ANY` | | `[{"id","name","webUiUrl","iconUrl","shell","support","project","managedBy"}]` |
| `GET /api/disks/state` | `ARRAY:READ_ANY` | | `[{"name","device","type","spundown","temp","status","rotational"}]` |
| `GET /api/array/encryption` | `ARRAY:READ_ANY` | | `{"status":"none"\|"new"\|"missing"\|"wrong"\|"present","keyfile":bool}`: the webGUI's Start-array encryption status, from disks.ini and var.ini |
| `POST /api/array/encryption/keyfile/delete` | `ARRAY:UPDATE_ANY` | | the new `{"status","keyfile":false}`; 409 unless the array is stopped and the saved keyfile is the wrong key (the webGUI's "Delete" of the encryption keyfile) |
| `POST /api/disks/spin` | `ARRAY:UPDATE_ANY` | `{"disk":"disk1"\|"all","action":"up"\|"down"}` | `{"ok":true}` |
| `GET /api/mover/status` | `ARRAY:READ_ANY` | | `{"running":false}` |
| `POST /api/mover/action` | `ARRAY:UPDATE_ANY` | `{"action":"start"\|"stop"}` | `{"ok":true,"running":bool}` |
| `POST /api/parity/action` | `ARRAY:UPDATE_ANY` | `{"action":"start"\|"pause"\|"resume"\|"cancel","correct":false}` | `{"ok":true}` |
| `GET /api/plugins` | `CONFIG:READ_ANY` | | `{"plugins":[{"name","file","version","author?","pluginURL?","support?","icon?","updateAvailable","latestVersion?"}]}` |
| `POST /api/plugins/check` | `CONFIG:UPDATE_ANY` | | same as `GET /api/plugins`, after `plugin checkall` |
| `POST /api/plugins/update` | `CONFIG:UPDATE_ANY` | `{"name":"ca.plg"}` | `{"ok":bool,"output":"..."}` (+ `"message"` = output when `ok` is false) |
| `POST /api/plugins/remove` | `ADMIN` | `{"name":"ca.plg"}` | `{"ok":bool,"output":"..."}` (+ `"message"` when `ok` is false) |
| `GET /api/disks/smart?device=sdb` | `DISK:READ_ANY` | | `{"device","standby","passed","temperature","powerOnHours","attributes":[{"id","name","value","worst","thresh","raw","failing"}]}` |
| `GET /api/files/list?path=/mnt/user` (`&offset=&limit=` optional) | `ADMIN` | | `{"path","parent","entries":[{"name","path","type":"dir"\|"file"\|"symlink","size","mtime","targetType"?,"protected"?}],"total","truncated"?,"offset"?,"next"?,"incomplete"?}` (`protected`: a denied `/boot` path, listed but never opened) |
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
  attributes numbered from 1. A device that cannot report SMART at all (USB bridge, virtual disk) answers `501`
  with `"code":"smart_unsupported"`. A temperature of exactly 0 with no attributes (what QEMU disks report)
  is `null`.
- **Files** are read-only. Paths are canonicalised (`..` refused, symlinks resolved) and must stay under
  `/mnt/user`, `/mnt/user0`, `/mnt/disk<N>`, `/mnt/cache`, `/mnt/<pool>` (pools from `/boot/config/pools/*.cfg`)
  or `/boot`; the resolved path is then opened one component at a time without following any symlink, and the
  opened descriptor is checked again. A name over 255 bytes or a path over 4095 bytes (3840 bytes
  under `/mnt/user` and `/mnt/user0`, where shfs rewrites the path to a longer disk or pool path) is refused
  with `400` before the filesystem is touched (an over-long name crashes Unraid's shfs). The same limits apply
  to symlink targets and to the path a link expands to, before anything below them is looked up: such a link is
  refused with `400` when opened and listed without `targetType`; a listed entry whose full path would exceed the
  limit is listed by name and type only (no size or `mtime`). More than 40 links in one path answer `500`
  (`too many levels of symbolic links`). Errors never echo the path; `403` is only a policy refusal (outside the
  roots, a protected file) or a permission error, and any other filesystem failure answers `500` with the
  system's reason only (e.g. `transport endpoint is not connected`, or a path swapped for a symlink while it
  was opened). Directories first, at most 5000 entries per page; `mtime` is
  Unix seconds. On `/boot`, `config/shadow`, `config/passwd`, `config/smbpasswd`, `config/ssh`, `config/ssl`,
  `config/wireguard`, `config/wireless.cfg`, `config/secrets.tdb`, `config/*.key` (license keys, any case),
  `config/rclone`, `config/plugins/rclone/.rclone.conf`, `config/plugins/dynamix.my.servers` and
  `config/plugins/raidman/settings.json` (and everything below them) are refused with `403`; they are matched
  by file identity, so case variants and symlinks are refused too.
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
| `POST /api/vm/action` | `VMS:UPDATE_ANY` | new action `reset` (feature `vm.reset`); unknown actions → `400`; an action the VM's state does not allow (`start` of a running, paused or otherwise active VM; `resume` of one that is not paused; `stop`, `force-stop`, `restart`, `pause`, `hibernate` or `reset` of a shut-off one; `reset` of one shutting down or suspended) → `409`, decided from the VM's state, read before the action and again if libvirt refuses it (a refusal while the VM is not in the state the action is meant for, e.g. `stop` or `pause` of a paused VM, is also `409`); any other failure → `500` with libvirt's message |
| `GET /api/vm/info`, `GET /api/vms` | `VMS:READ_ANY` | `interfaces[].ipAddresses` (feature `vm.ips`), `hostdevs[]` (feature `vm.hostdevs`), `detailedState` `blocked` / `shutdown` |
| `POST /api/vm/autostart` | `VMS:UPDATE_ANY` | `enabled` is required (`400` without it; older plugins turned autostart off) |

An unknown VM on `/api/vm/action`, `/api/vm/autostart` or `/api/vm/info` answers `422` `{"error","code":"not_found"}`
(older plugins: plain-text `500`). `409` bodies stay plain text: a short reason (`VM is already running`, `VM is not
running`, `VM is not paused`) or, when the state changed while libvirt ran the action, libvirt's message. libvirt's
"Requested operation is not valid" alone is not a state conflict (it also means a passthrough device in use, an
inactive network, ...): it answers `500` with libvirt's message, on `/api/vm/autostart` too. A failed force-stop and
start of the `reset` fallback is a `500`.

### Docker actions (protocol-1 route)

`POST /api/docker/action` answers an unknown container with `422` `{"error","code":"not_found"}`, an unknown action
with `400`, and an action the container's state does not allow (pause a paused container, unpause a running one,
kill or pause a stopped one) with a plain-text `409` and a short message without the container id
(`container is already paused`, `container is not paused`, `container is not running`, ...). Older plugins
answered these with `500` and the daemon's text.

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
| `docker` (exec) | `ADMIN` | `container`, `shell` (optional: `sh` default, `bash`, `ash`, `zsh`; anything else → error frame) |
| `vm-log` | `VMS:READ_ANY` | `vm` |
| `vm` (serial) | `ADMIN` | `vm` (name or UUID) |
| `vm-vnc` | `VMS:UPDATE_ANY` | `vm` (name or UUID) |
| `host` | `ADMIN` (and enabled in settings) | |

Container ids may be raw Docker ids, names, or Unraid API PrefixedIDs (`<serverId>:<id>`).

Invalid parameters (any stream), an unknown container on `docker-stats`, an unknown VM on `vm` and `vm-log`, and
every `vm-vnc` error (unknown VM, VM not running) send one text frame starting with `Error` and then close with
`1000`. `vm-log` refuses a VM that libvirt does not know only when it also has no log file; the log of a deleted
VM is still served. (`docker`/`docker-log` on a missing or stopped container send the docker CLI's message and
close with `1000` `process exited (1)`.)

Terminals start at 80x24 until the client sends its size. Closing a container console (`docker`), or losing
its connection, ends it like an ssh disconnect: the shell started in the container (identified while the
console is open by a random `RAIDMAN_EXEC=<tag>` variable, among that container's processes only, and recorded
by pid and start time) and the terminal's foreground job are hung up (`SIGHUP`); after 3 s the shell and
whatever is still in its session are killed, except processes that ignore `SIGHUP`. If the shell already exited
(`exit`, Ctrl-D), only what is left in its session is hung up and then killed. Deliberately detached work
survives: `nohup` jobs, and anything that left the session (`setsid`, daemons, the `tmux`/`screen` server),
even though it carries the same variable; it is never mistaken for the shell. If the connection dropped before
the shell was seen and the shell cannot be told apart unambiguously at the end, nothing is signalled.
Interactive programs and plain background jobs end with the console. Older plugins only stopped the
`docker exec` client, which left the shell and its children running in the container.

**Terminal resize** (`host`, `docker`, `vm`): send a *text* frame that is exactly either
`\x1b[8;<rows>;<cols>t` or the JSON object `{"type":"resize","cols":N,"rows":M}` (1–1000). Any other frame
is terminal input. Older plugins write such frames to the terminal, so only send them when `/api/health`
lists `terminal.resize`.

Sockets accept messages up to 64 KiB (4 MiB for VNC), ping every 30 s, and are closed with code `1008`
when the key is deleted or loses the permission.

## Development checks
The CI workflow runs these; all but `test-rc.sh` also work locally (`xmllint`, GNU tar for packaging):
- `go vet ./... && go test -race ./...`
- `scripts/check-plg.sh`: `raidman.plg`, `raidman.xml` and `ca_profile.xml` are well-formed, the plg's entities
  resolve, every downloaded `<FILE>` has a SHA-256, and the inline install/remove scripts and all shell scripts
  pass `bash -n` (and shellcheck when installed). `--allow-unstamped` accepts an empty SHA-256.
- `scripts/build.sh <version> [out]`: the release binary (linux/amd64, `CGO_ENABLED=0`, version via `-ldflags`),
  smoke-tested with `-version` on linux/amd64.
- `NOVNC_VERSION=… NOVNC_SHA256=… scripts/package.sh <version> <binary> <outdir>`: the reproducible package
  (values from the workflow), then `scripts/check-package.sh <tgz>` checks it holds exactly what the install
  script expects.
- `scripts/test-rc.sh <linux binary>` (Linux only): start, crash restart, stop and double start of `rc.raidman`.
- `scripts/check-released.sh` (needs network): downloads the package `raidman.plg` points at, checks its
  SHA-256 and runs `check-package.sh` on it with this plg, so a change to the install script on `main` cannot
  break installs of the current release.

## Releasing
The release tag is the plugin version (`YYYY.MM.DD`, or `YYYY.MM.DDa` for a second release on one day).
Nobody edits `<!ENTITY version>` or `<!ENTITY sha256>` in `raidman.plg` by hand: the copy on `main` always
describes the last published package, because installed servers and Community Applications read it there.

1. In a normal pull request, add `<CHANGE>YYYY.MM.DD - what changed</CHANGE>` at the top of `<CHANGES>` in
   `raidman.plg` (the release fails without an entry for its tag) and update `<Date>` in `raidman.xml`.
   Use the actual release day for the tag, `<CHANGE>` and `<Date>` (not the day the pull request was opened),
   so CA Auto Update's age delay counts from the release.
   Merge it once CI is green.
2. Tag the commit on `main` and push the tag: `git tag 2026.12.01 && git push origin 2026.12.01`.
3. The release job then:
   - checks the tag format, the `<CHANGE>` entry, that `main` is not already at a newer version, and whether the
     release already exists;
   - builds the binary and the reproducible package (fixed mtime, sorted, owner 0, `gzip -n`, noVNC included);
   - stamps the tag and the package SHA-256 into `raidman.plg`, publishes the release with the package, its
     `.sha256` and the stamped `raidman.plg` (an existing release is never overwritten). The release notes end
     with `Source commit: <sha>`, the tagged commit the package was built from; do not edit that line;
   - downloads the published package, checks its SHA-256, and commits the two stamped lines to `main`'s own
     `raidman.plg` (retrying on push races). It does so only if the tagged commit is an ancestor of `main`, or
     `main` differs from it only in `raidman.plg`.
4. If the job fails after publishing (for example the push to `main` was rejected, or the run was cancelled
   while the release was still a draft), re-run it. It reuses the published package only if the release notes
   name the same commit (`Source commit:`) and the package passes `scripts/check-package.sh`; it uploads a
   missing `.sha256` or `raidman.plg` asset, publishes a leftover draft, and stamps `main`. A release made by
   hand, by an older workflow, or for a tag that has since moved is refused: to change a published package,
   release a new tag.

A pull request that makes the install script need a new file (a new `REQUIRED_FILES` entry) cannot pass the
"Install script fits the released package" step, because the current release lacks that file. Release it from
the pull request's head as described next instead of merging it first.

A tag that is not on `main` still publishes its release, but `main` is not stamped, so no server is offered
the update. That is also how the first release of this packaging is bootstrapped: tag the pull request's head,
copy the two stamped lines from the release's `raidman.plg` into the pull request (its strict `check-plg`
step fails until then), then merge it.

## Support
- **Issues**: [GitHub Issues](https://github.com/routecore/raidman-plugin/issues)
- **Security**: security@raidman.app

## License
Distributed under the MIT License. See `LICENSE` for more information.
