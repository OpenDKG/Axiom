# Linux

This document describes the Linux build of Axiom. Windows remains the reference platform; this
page states exactly what is implemented, what is partial and what is not available, so the
interface never claims more than the OS result.

## Status

Implemented and exercised on Linux x64 (Ubuntu 24.04, kernel 7.0.0, root in a privileged
container with cgroup v2, libbpf 1.3 and clang 18 for the eBPF object):

| Capability | Linux implementation | Notes |
|---|---|---|
| TCP/UDP inventory, IPv4 and IPv6 | `/proc/net/{tcp,tcp6,udp,udp6}` with `readlink` on `/proc/<pid>/fd` | PID plus kernel start time, so a recycled PID is a new process |
| Process attribution | `/proc/<pid>/exe`, `comm`, `stat` | Unreadable processes stay `partial`; kernel/TIME_WAIT rows use PID 0 |
| First-seen/new-flow tracking | same contract as Windows | Connections shorter than the poll interval can be missed |
| History (SQLite) | unchanged `Axiom.Persistence` | WAL, retention, search; valid-header page corruption is quarantined with the WAL/SHM evidence copied before SQLite can checkpoint it |
| History CSV export | `/api/history.csv` in the Linux UI | RFC 4180 escaping, UTF-8 BOM, spreadsheet-formula neutralisation, 100k row cap |
| Service lifecycle | systemd system or user unit | System scope sees every process; user scope is sandboxed by the session |
| Local IPC | Unix domain socket in a private directory, `SO_PEERCRED` uid check | 0600 socket, 0700 directory (0711 when another uid is allowed); no TCP listener; same protocol, caps, rate limit and deadlines |
| MCP server | unchanged tools over the Unix socket transport | Verified against the real service, not a mock |
| Browser UI | `Axiom.Desktop.Linux`, loopback only, per-run token | No remote listener, no shell, CSP, frame denial, loopback Host check |
| Privacy Shield DNS filter | `Axiom.Dns`, loopback design | Host resolver as upstream, including `127.0.0.53`; no public fallback; in-flight queries are drained on shutdown; never changes system DNS settings |
| **Per-executable firewall** | eBPF cgroup hooks (`connect4/6`, `sendmsg4/6`, `bind4/6`) | Opt-in write gate; executable identity by dentry-path hash; read-back, rollback, link-owned cleanup |
| Credential storage | Secret Service through `secret-tool` | No plaintext fallback: writes fail with an explicit error when no keyring/session bus exists |
| AI analyst | portable OpenAI-compatible client + Linux settings and key storage | Bounded evidence package; paths redacted by default; optional, no automatic analysis loop |
| Reputation | VirusTotal hash-only client | The local file is hashed locally; only the SHA-256 leaves the host |
| Autostart | XDG `~/.config/autostart/axiom.desktop` | Marker-owned entry, absolute `Exec`, refuses unowned/symlinked files |
| Desktop notifications | not claimed; the browser UI is the status surface | There is no tray icon on Linux (see below) |
| Packaging | self-contained tarball and `.deb` | `scripts/package-deb.sh`; the package does not enable/start the service or touch firewall/DNS |

### Per-executable firewall

The Linux adapter (`Axiom.Infrastructure.Linux/Firewall`) loads a small CO-RE eBPF object through
`libbpf` and attaches it to the cgroup v2 hierarchy at the socket-address hooks. The kernel compares
the **executable of the calling task** with the policy maps:

- identity is a 128-bit hash of the executable's filesystem device (`d_sb->s_dev`, mirrored from
  the `major:minor` field of `/proc/self/mountinfo`) and its filesystem-internal path, derived from
  the dentry chain (`task->mm->exe_file`) in the kernel and from the canonical path in userspace.
  Two filesystems exposing the same internal path therefore do not share a rule. It is stable
  across PID reuse, restarts, bind mounts and mount namespaces. A replacement binary at the same
  path *does* inherit the rule (the identity is path-based, not inode-based), and an already
  running deleted binary keeps matching until it exits; the adapter refuses to manage or remove
  that rule while the path cannot be resolved. Path components are limited to 7 and 64 bytes each,
  deeper paths are refused rather than truncated;
- rules support block/allow, TCP/UDP/any, port and port-range lists, and IPv4/IPv6 CIDR scope;
- a **block** match denies the operation (`EPERM` for connect/sendmsg, an error for bind);
- an executable with at least one **allow** rule for a direction is in allow-list mode: unmatched
  traffic for that executable and direction is denied. This is deliberately stricter than a
  Windows profile default and is shown in the rule's verification notes;
- every unmatched executable is untouched, so installing Axiom does not silently filter unrelated
  traffic;
- outbound rules cover TCP `connect`, connected and unconnected UDP; inbound rules cover new
  `bind`/`listen` calls only. Inbound allow rules, inbound remote-address scope and inbound
  remote-port scope are refused with `rule.scope.unsupported_platform` because a bind hook cannot
  see the future peer and `RuleSpec.RemotePorts` means the peer port, not the local one. An
  accepted inbound block therefore applies to every new bind of that executable. A socket bound
  before the rule is not torn down.

Writes require `AXIOM_ENABLE_FIREWALL_WRITES=1` and `AXIOM_FIREWALL_WRITE_CONFIRM=yes`, the
same gate as Windows. Apply is transactional: the old slots are snapshotted, the new slots are read
back from the kernel maps, and a mismatch restores the snapshot. `libbpf` links are owned by the
service process and are never pinned, so a crash or exit detaches enforcement instead of leaving a
stale program attached. The system unit's `ProtectControlGroups=true` must be relaxed for this
feature; `packaging/linux/axiom-firewall.conf` is the opt-in drop-in, and the capability report
stays `unavailable` with the exact reason when the prerequisites are missing.

Prerequisites: kernel with BTF and cgroup v2, `libbpf1`, `CAP_BPF` + `CAP_NET_ADMIN`
(`CAP_SYS_ADMIN` for some kernels), and write access to the cgroup hierarchy. Without them the
Firewall page reports the reason; no rule is installed and nothing is silently downgraded to a
UID/port rule.

Evidence: live tests attach the real object to a disposable child cgroup and verify TCP block,
UDP sendmsg block, bind block, allow-list mode, non-matching processes, removal, and that no
socket outside the test cgroup is affected. The service + UI smoke run reported the backend as
`available` with the write gate closed and never changed host firewall/DNS state.

### Agent hooks and optional modules

- **Agent hook installers** remain unresolved. The hook payload calls the Blackbox Python module,
  which is distributed only as a pinned Windows installer. Installing a Linux hook without that
  module would create a hook that fails open; the Linux build therefore installs none and says so.
  The installers, trust checks and ownership rules stay in the WPF project.
- **Blackbox** is not installable on Linux: there is no verified Linux artifact to pin.
- **DKG** is an npm package and works on Linux, but this build does not detect, download or install
  it. Use the documented CLI commands in a user-scope prefix; no Linux page reports a DKG status.
- **AI analyst** is optional and disabled until configured. The provider key is stored by Secret
  Service; without a keyring the UI refuses to store it. Only the bounded evidence package leaves
  the host.
- **Reputation** is hash-only and needs a VirusTotal key. The Linux UI has no field for that key
  (`virustotal` credential), so the reputation action reports a missing key until one is stored by
  another Secret Service client; only the SHA-256 would leave the host. No live provider call was
  exercised.

### Tray icon, autostart and packaging

Linux desktops have no portable tray API without a shell extension (GNOME hides legacy trays), so
this build does not claim a tray icon. The supported equivalent is the loopback UI plus an XDG
autostart entry (About → *Start Axiom at login*), which is written only for the installed
`Axiom.Desktop.Linux` apphost. `.deb` packaging installs the service unit and the desktop entry;
the firewall drop-in is shipped as an example under
`/usr/share/doc/axiom/examples/`, not enabled, because it relaxes `ProtectControlGroups`. The
package does not start the service and never deletes `/var/lib/axiom`. The unit starts with
`AXIOM_ALLOWED_UID=0` (root only); the post-install message shows the drop-in that authorises the
desktop user before the service is enabled, and the browser UI must not be run as root.

### WSL, containers and confined hosts

The host detector reports WSL, container cgroups (`docker`/`kubepods`/`/.dockerenv`), active LSMs,
the AppArmor profile and SELinux enforcing mode as limitations in the snapshot. Those facts are
**reported, not claimed as tested**:

- under WSL, systemd, cgroup v2 and BPF availability depend on the WSL version and `.wslconfig`;
- inside a container, attribution is limited to the container's namespaces and firewall
  enforcement needs a delegated cgroup v2 hierarchy plus `CAP_BPF`/`CAP_NET_ADMIN`;
- AppArmor/SELinux profiles can deny BPF, `/proc` or socket creation. This build reports the
  restriction and does not attempt to bypass it. No confined-host runtime was exercised for this
  pass.

Not available on Linux in this build, and reported as such:

- agent hook installation (Blackbox dependency, above);
- tray icon (no portable API; autostart and the browser UI are the supported path);
- MSIX/Microsoft Store (Windows distribution only);
- macOS (not implemented and not claimed; see the follow-up section).

## Requirements

- Linux x64 with a kernel that has `/proc` (all supported distributions).
- .NET 10 SDK to build; published builds are self-contained.
- systemd for service lifecycle (a system manager for `--system`, a user manager for `--user`).
  The service binary also runs in the foreground for development.
- No root required for the UI, monitoring of your own processes, history or autostart. Root
  (`system` install) is needed to attribute sockets of every process and to attach the eBPF firewall
  programs; the exact missing capability is reported by the Firewall page.

## Build, test, publish

```bash
./scripts/build-linux.sh
./scripts/publish-linux.sh        # self-contained; SELF_CONTAINED=0 for framework-dependent
```

`build-linux.sh` uses `Axiom.Linux.slnf`; the WPF/Windows projects are built by the Windows
toolchain. The Linux tests include the real `/proc` parser, Unix socket authentication, live eBPF
enforcement on a disposable cgroup, Privacy Shield DNS and the existing
Contracts/Core/Persistence/Service/MCP suites.

The service and its test project select `net10.0` on Linux and `net10.0-windows` on Windows, so a
single NuGet lock graph cannot describe both. Both projects therefore disable
`RestorePackagesWithLockFile` on every platform and rely on the central version pins in
`Directory.Packages.props`; their transitive graph is not locked, unlike the rest of the solution.
`dotnet restore Axiom.sln --locked-mode` therefore covers every project except those two, on either
platform.

## Install

```bash
./scripts/install-linux.sh --system --allow-uid "$SUDO_UID"   # full process attribution
./scripts/install-linux.sh --user                              # no privileges
```

- `--system` installs under `/opt/axiom`, writes `/etc/systemd/system/axiom.service` and
  allows exactly one uid to call the service. The service runs as root only because `/proc` and
  `/proc/<pid>/fd` of other users require it.
- `--user` installs under `~/.local/opt/axiom` with a systemd user unit and a desktop entry.
- The installer never changes firewall, proxy or DNS settings, never installs Blackbox/DKG and
  never downloads anything. Payload hashes are written to `install-manifest.sha256`. A system
  install owns its copied payload as root and rejects symlink or setuid payloads.
- The user installer writes an absolute, validated desktop entry; `%h` is not a Desktop Entry
  expansion.
- Local data is kept on uninstall unless `--remove-data` is passed.

Run the UI:

```bash
~/.local/opt/axiom/ui/Axiom.Desktop.Linux
# or, from a checkout:
dotnet run --project src/Axiom.Desktop.Linux -- --port 5600
```

The UI prints `http://127.0.0.1:<port>/#t=<token>` and tries `xdg-open`. The token is kept in
`sessionStorage` and sent as `X-Axiom-Token`; it is never put in a query string or a cookie.
With browser auto-open enabled the token-bearing URL is passed to `xdg-open` as a process argument,
so another local account that can read the process table can observe it during launch; run with
`--no-browser` where that matters (the headless unit below does).

### Headless server (system service, unprivileged UI unit)

A server has no desktop session, so the supported shape is the system service above plus a small
local unit that runs the loopback UI as a separate unprivileged uid. Both processes then start at
boot without a login:

```ini
# /etc/systemd/system/axiom-ui.service
[Unit]
Description=Axiom loopback browser UI (unprivileged IPC client)
After=axiom.service
Wants=axiom.service

[Service]
Type=simple
User=axiom-ui
Group=axiom-ui
Environment=HOME=/var/lib/axiom-ui
Environment=XDG_CONFIG_HOME=/var/lib/axiom-ui/.config
Environment=XDG_DATA_HOME=/var/lib/axiom-ui/.local/share
ExecStart=/opt/axiom/ui/Axiom.Desktop.Linux --no-browser --port 5600 --socket /run/axiom/service.sock
StateDirectory=axiom-ui
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`AXIOM_ALLOWED_UID` in `axiom.service` must be the UI uid. `StateDirectory=axiom-ui` creates
`/var/lib/axiom-ui` owned by that uid and keeps it writable under `ProtectSystem=strict`, which is
where AI settings and the autostart entry are stored. The unit is site-local, not shipped: the UI
remains an ordinary IPC client and the service stays the only privileged process. No remote listener is opened; on a headless host reach
`127.0.0.1:5600` through an SSH local-forward. The per-run token is printed to the unit's stdout
(journal, readable by root and `adm`), so keep the journal restricted accordingly.

## Paths and environment

| Setting | Default | Purpose |
|---|---|---|
| `AXIOM_DATA_DIR` | `/var/lib/axiom` for a root service, `$XDG_DATA_HOME/Axiom` otherwise | SQLite database and Privacy Shield files; must be a private, dedicated directory |
| `AXIOM_IPC_SOCKET` | `/run/axiom/service.sock` for root, `$XDG_RUNTIME_DIR/axiom/service.sock` otherwise | Client and server endpoint override |
| `AXIOM_ALLOWED_UID` | service uid | The only uid allowed to call the socket |
| `AXIOM_ENABLE_FIREWALL_WRITES` + `AXIOM_FIREWALL_WRITE_CONFIRM` | unset | Both are required before the eBPF adapter may attach or change a rule |
| `AXIOM_FIREWALL_CGROUP` | `/sys/fs/cgroup` | Attach point; tests point it at a disposable child cgroup so the host is never filtered |

Socket permissions: the parent directory is 0700, or 0711 when a different uid is allowed so that
user can traverse but not list it; the socket is 0600 and owned by the allowed uid. The server checks
`SO_PEERCRED` before parsing any byte. A populated directory that is not private is refused instead
of being chmod-ed; use a dedicated directory.

Data directories follow the same rule and must be owned by the service uid. An existing
world-readable directory containing files is rejected rather than chmod-ed in place, so
`AXIOM_DATA_DIR=/tmp` fails with a clear error instead of changing `/tmp` or exposing history;
a directory owned by another user is rejected even when its mode is 0700.

Do not add `PrivateTmp=yes` to the unit. On systemd versions that implement it with an idmapped user
namespace, the service loses `CAP_SYS_PTRACE` over host processes and can no longer attribute their
sockets; the UI then shows every row as `partial`. This was observed during implementation and is
why the shipped units omit it.

## macOS follow-up

`IServicePlatform` is the seam. Porting needs:

- a `/proc` replacement (`libproc` `proc_pidinfo`, `sysctl`), including a socket-to-pid map;
- peer credentials for Unix sockets (`getpeereid`/`LOCAL_PEERCRED`);
- `pf` anchors with `pfctl` (or a Network Extension) for enforcement, with the same owned-rule
  read-back and rollback guarantees;
- a `launchd` job instead of systemd;
- a UI packaging decision; the loopback browser UI is portable.

None of this is implemented, and no macOS compatibility is claimed.
