# Axiom for Linux — port plan

Status: proposal, 2026-11-12. Baseline: branch `buba/macos` @ 54ecacc (worktree `/home/buba/projects/Axiom-mac-filter`).
Target: x64/arm64, systemd distros with cgroup v2 and nftables (Ubuntu 24.04+, Fedora 42, Arch), GNOME/KDE on X11 and Wayland.
Evidence box: Ubuntu 24.04.5, kernel 7.0.0-42-generic, nft 1.0.9, systemd 255, cgroup2fs, `unprivileged_bpf_disabled=2`,
GNOME on X11, systemd-resolved stub + NetworkManager (netplan). Spike: `spike/enforcement-spike.sh` → `spike/spike-output.txt`.

## 1. Components (Linux counterpart per macOS piece)

| macOS piece (as built) | Linux counterpart | Project |
|---|---|---|
| `Axiom.app` → `Axiom.Desktop.Avalonia.MacOS` | `axiom` desktop (X11 now, Wayland when Avalonia ships it); `Axiom.Desktop.Avalonia.Linux` as `CROSS_PLATFORM_UI_HANDOFF.md` §8 expects | new `src/Axiom.Desktop.Avalonia.Linux` |
| `axiomd` launchd daemon (`Axiom.Service` net10.0) | same `axiomd` binary under a systemd unit `axiomd.service` | `src/Axiom.Service` (+ `ServicePlatform.Unix.cs` split per OS) |
| `Axiom.Service.Hosting` seams | unchanged | — |
| `UnixSocketIpcTransport` + `PeerAuthorization` (getpeereid) | same class; `UnixPeerCredentials` already has the `SO_PEERCRED` branch; socket at `/run/axiom/axiom.sock` | move to `src/Axiom.Infrastructure.Unix` |
| AxiomFilter NE system extension + `rules.json` + `filter.sock` NDJSON | `NftFirewallPolicyAdapter`: nftables table `inet axiom` with `socket cgroupv2` rules (P2), later `axiom-bpf` helper speaking the same NDJSON flow protocol over `/run/axiom/filter.sock` (P2b) | new `src/Axiom.Infrastructure.Linux/Firewall` |
| `MacConnectionSource` + `LibProcSocketScanner` (libproc) | `ProcNetConnectionSource`: `/proc/net/{tcp,tcp6,udp,udp6}` + one `/proc/*/fd` inode scan per 2 s (same contract, same `FlowTable`) | `src/Axiom.Infrastructure.Linux/Monitoring` |
| `MacProcessIdentityResolver` (proc_pidpath, codesign, bundle) | `/proc/<pid>/exe` realpath, `/proc/<pid>/cgroup`, `.desktop` id from the systemd scope name (`app-gnome-org.mozilla.firefox-1234.scope`), Flatpak id from `/proc/<pid>/root/.flatpak-info`, package owner via `dpkg -S`/`rpm -qf` (cached) | `src/Axiom.Infrastructure.Linux/ProcessIdentity` |
| `MacDnsConfigurator` + `MacPrivacyDnsPlatform` (`networksetup`) | `LinuxDnsConfigurator`: systemd-resolved first (`resolvectl dns/domain/revert <link>`), NetworkManager second (`nmcli con mod … ipv4.dns`), `/etc/resolv.conf` last (backup + atomic rewrite) | `src/Axiom.Infrastructure.Linux/Dns` |
| `MacDnsProcessLookup` (`IDnsProcessLookup`) | `ProcDnsProcessLookup`: UDP/TCP source port → inode (`/proc/net/udp`) → pid (fd scan, shared with the connection scanner) | `…/Linux/Dns` |
| `LaunchdServiceInstaller` + `PrivilegedHelperLayout` audit | `SystemdServiceInstaller`: copy publish dir to `/usr/libexec/axiom` (root 0755), audit (`PrivilegedHelperLayout` reused as is), write unit, `systemctl daemon-reload && enable --now` | `…/Linux/Systemd` + audit moved to Unix |
| `MacDataDirectoryPermissions` (`/Library/Application Support/Axiom`) | same code on `/var/lib/axiom` (`AxiomPaths` already returns it) | move to Unix (rename `UnixDataDirectoryPermissions`) |
| `MacDoctor` | `LinuxDoctor`: unit state, `/usr/libexec/axiom` audit, sockets, data modes, nft table present, resolved/NM DNS state, backup file | `…/Linux/Diagnostics` |
| `osascript … with administrator privileges` | `pkexec /usr/libexec/axiom/axiomd --install-service` with a polkit action `com.axiom.firewall.install` (`auth_admin_keep`) | desktop host |
| Keychain (`KeychainApiKeyProtector`) | Secret Service (`org.freedesktop.secrets`, libsecret via Tmds.DBus/`dbus-send`-free P/Invoke) + file fallback 0600 in `~/.config/axiom` | desktop host |
| `MacAutostartService` (LaunchAgent) | `~/.config/autostart/com.axiom.firewall.desktop` (`X-GNOME-Autostart-enabled`, `Exec=axiom --autostart`) | desktop host |
| `MacThemeService` | `org.freedesktop.portal.Settings Read org.freedesktop.appearance color-scheme` (verified on this box: returns `u 1` = dark) + signal `SettingChanged` | desktop host |
| `MacSingleInstance` (flock + Unix socket in user dir) | identical code, socket under `$XDG_RUNTIME_DIR/axiom/desktop.sock` (0700 dir, verified) | move to Unix |
| Menu-bar status item | Avalonia `TrayIcon` = StatusNotifierItem over D-Bus; needs an SNI host (KDE native, GNOME needs the AppIndicator extension; on this box no `org.kde.StatusNotifierWatcher` is registered → tray absent, app must not depend on it) | desktop host |
| `ChildSignal` SIGCHLD re-exec | not needed under pkexec; keep the class, it is a no-op off macOS | stays macOS |
| `.pkg` + `package-app.sh` | `.deb` + `.rpm` (nfpm or `dotnet publish` + `fpm`), AppImage for the desktop only, no Flatpak for the daemon | `scripts/linux/` |

## 2. Reuse plan: `Axiom.Infrastructure.Unix`

Grep of `src/Axiom.Infrastructure.MacOS` for macOS markers (`IsMacOS`, libproc, networksetup, launchctl, `/Library`) shows 22 of 36 files have none. Move these verbatim (namespace `Axiom.Infrastructure.Unix`, tests follow):

| Move to `Axiom.Infrastructure.Unix` (Unix-generic) | Stay in `Axiom.Infrastructure.MacOS` (macOS-only) |
|---|---|
| `Ipc/UnixSocketIpcTransport`, `Ipc/PeerAuthorization` (parametrise the uid floor: 501 macOS / 1000 Linux via `UnixAccounts.FirstUserUid`, and the admin group: `admin` / `sudo`+`wheel`) | `Interop/LibProc*`, `Interop/ChildSignal` |
| `Interop/UnixSocketListener`, `UnixPeerCredentials` (Linux branch exists), `UnixFileStat`, `UnixGroups`, `ProcessRunner` | `Dns/MacDnsConfigurator`, `NetworkSetupParser`, `MacPrivacyDnsPlatform`, `MacDnsProcessLookup` |
| `Filter/FilterRulesFile`, `FilterRuleTable`, `FilterStatus`, `FlowEvent`, `FilterEventServer`, `BoundedLineReader` → the NDJSON flow contract becomes the Unix "filter backend" protocol | `Monitoring/MacConnectionSource`, `ProcessIdentity/Mac*`, `CodeSignatureInfo` |
| `Monitoring/FlowTable` | `Launchd/LaunchdServiceInstaller`, `Diagnostics/MacDoctor`, `MacServicePaths` → split: generic `UnixServicePaths` base + per-OS socket/log/install dirs |
| `Launchd/PrivilegedHelperLayout` (audit), `InstallOwner` (`SUDO_UID`; add `PKEXEC_UID`) | `Filter/MacFirewallPolicyAdapter` → extract the rule → `rules.json` translation and `FilterEnforcement` reporting into `Unix/Filter/FilterBackendPolicyAdapter`; the macOS class keeps only the paths |
| `MacDataDirectoryPermissions` → `UnixDataDirectoryPermissions` | |
| `ProcessIdentity/IProcessIdentitySource` | |

`Axiom.Service.csproj`: keep `net10.0` single Unix TFM; select the infrastructure project by `$(RuntimeIdentifier)` prefix (`osx-*` → MacOS, `linux-*` → Linux) and split `ServicePlatform.Unix.cs` into `ServicePlatform.MacOS.cs` / `ServicePlatform.Linux.cs` (same shape: `TryRunCommand`, `ConfigureServices`). `AxiomPaths` already knows `/var/lib/axiom`; add `RuntimeDirectory` = `/run/axiom` (Linux) / `/var/run/axiom` (macOS) and make `IpcPipe.Endpoint` use it. Desktop: `MacSingleInstance`, `StartupLog`, `ProcessActions` (kill/open folder: `xdg-open`) move to a small `Axiom.Desktop.Avalonia.Unix` shared source folder (or a `Shared` items project) rather than a third assembly.

## 3. Enforcement decision (evidence in `spike/spike-output.txt`)

**Decision: (a) nftables `socket cgroupv2` per-app cgroup rules now; (b) eBPF cgroup `connect4/6` + `sock_ops` via a small C helper as the Phase-2 attribution/flow-event backend; (c) NFQUEUE only as a fallback for kernels without `nft_socket`. (d) LD_PRELOAD/seccomp rejected.**

What the spike showed on this box (all with real `curl`):

- cgroup v2 unified hierarchy; `nft_socket`, `nft_queue`, `nfnetlink_queue`, `xt_cgroup` modules present and loading; bpftool (root) reports `cgroup_sock_addr`, `cgroup_skb`, `sock_ops` available, 10 cgroup-BPF programs already attached by systemd/docker (co-existence is normal).
- `unprivileged_bpf_disabled=2`: every BPF path is root-only; fine for the daemon, impossible for the desktop app.
- **Rule insertion requires the cgroup to exist** (`nft add rule … socket cgroupv2 level 5 "…/axiom-spike.scope"` → ENOENT until the scope existed). `nft list` then shows the rule as a numeric **cgroup id** (`4648572`), confirmed by `nft_socket.c` (`cgroup_id(cgrp)` compared with the id resolved at insert time). A rule therefore dies with its cgroup: rules must be regenerated whenever the target cgroup is recreated.
- A `systemd-run --user --scope curl` was blocked: `curl: (7) … Couldn't connect`, counters `packets 2`, `reject with tcp reset` gives an immediate refusal (better UX than the macOS SYN drop; `drop` remains available for parity).
- An **already-running** process moved by root into a daemon-owned cgroup (`mkdir /sys/fs/cgroup/axiom-spike.slice/app1; echo $pid > cgroup.procs`) was blocked by a rule on that cgroup. So (a) is not limited to apps launched by Axiom.
- `/proc/net` inode → `/proc/*/fd` attribution works (own socket resolved; 2 869 fds scanned in 8 ms as a user).

Design derived from it (`NftFirewallPolicyAdapter` + `CgroupPlacer`):

1. One table `inet axiom` (flushed and rebuilt atomically with `nft -f` from a generated file `/var/lib/axiom/filter/rules.nft`, the Linux twin of `rules.json`; chains `out` (hook output) and `in` (hook input), policy accept, loopback exempt by an early `oif lo accept` unless the rule names loopback, exactly the §3.1 semantics).
2. Rule ⇒ cgroup resolution: for each enabled rule, pid scan (`/proc/*/exe` realpath == `appPath`, or inside it) → `/proc/<pid>/cgroup`. If the cgroup is exclusive to that executable (GNOME/KDE launch desktop apps in `app-<launcher>-<id>-<pid>.scope`, verified: user scopes land in `user@1000.service/app.slice/`), key the rule on that cgroup. If it is shared (terminal children, services), move the pid tree into `/sys/fs/cgroup/axiom.slice/<ruleid>/` (persistent while the daemon runs) and key the rule on that. Rules use an nft `set` of `cgroupsv2` ids per rule so the chain never changes shape; sets are updated with `nft add element` when apps start (proc connector netlink `PROC_EVENT_EXEC`, fallback 1 s `/proc` poll) and pruned when the cgroup disappears.
3. Reporting through the existing `FilterEnforcement` contract: a rule whose cgroup is shared and could not be isolated is reported as *rejected* with the reason, never silently widened — same UX as the macOS rejected-rules block.
4. Flow events for the Connections page come from `ProcNetConnectionSource` (poll) until the BPF helper exists; blocked connections are logged with `log prefix "axiom-block " group 1` (nflog) so blocks show up in events without NFQUEUE.
5. Phase-2 `axiom-bpf` (C, libbpf, CO-RE, ~400 lines, shipped as a separate root-only executable in `/usr/libexec/axiom`): `cgroup/connect4`, `connect6`, `sendmsg4/6`, `sock_ops` on the root cgroup, pinned maps under `/sys/fs/bpf/axiom`, ring buffer → NDJSON on `/run/axiom/filter.sock` using the macOS `flow.open/close/stats` contract so `FilterEventServer`, `FlowTable`, `FilterStatus` are reused unchanged. It can also enforce (verdict in `connect4`) which makes rule 2's cgroup placement unnecessary where it runs; nft stays as the fallback and for inbound.

Why not (c) first: NFQUEUE puts every new connection on a userspace round trip and still needs packet → pid lookup (OpenSnitch moved to eBPF for that reason, LWN 988401); it is the right fallback for distros without `nft_socket`, nothing more. Why not (b) first: no libbpf binding for .NET, root-only, CO-RE needs BTF (present on all three target distros, but a VM matrix is needed); the nft path ships in weeks with zero native code.

## 4. Privacy Shield DNS

Linux today: `/etc/resolv.conf → /run/systemd/resolve/stub-resolv.conf` (`nameserver 127.0.0.53`), stub listens on `127.0.0.53:53` and `127.0.0.54:53` only, so `DnsProxyServer` on **127.0.0.1:53 is free** and no port change is needed. NetworkManager owns the links and pushes per-link DNS into resolved on every (re)connect.

`LinuxPrivacyDnsPlatform` (implements `IPrivacyDnsPlatform`, `RediscoversUpstreams = true`), in order of detection:

1. systemd-resolved running (`busctl status org.freedesktop.resolve1`): per active link with a default route, save current `resolvectl dns/domain <link>` to `/var/lib/axiom/privacy-shield-dns-backup.json` (0600, same file as macOS), then `resolvectl dns <link> 127.0.0.1` + `resolvectl domain <link> '~.'`; restore with `resolvectl revert <link>`. Upstreams for the proxy = the saved per-link servers (+ `resolvectl status` global). A `NetworkManager` dispatcher script `/etc/NetworkManager/dispatcher.d/50-axiom` (installed with the unit) re-applies on `up`/`dhcp4-change`, since NM re-pushes DNS.
2. NetworkManager without resolved: `nmcli con mod <uuid> ipv4.dns 127.0.0.1 ipv4.ignore-auto-dns yes` (+ ipv6 `::1`), `nmcli con up`; restore from backup.
3. Plain `/etc/resolv.conf`: back up, write `nameserver 127.0.0.1` atomically; fail-safe on daemon start identical to macOS (`PrivacyDnsFailSafe` is already Unix-generic in spirit; `--restore-dns` reused).

App attribution of DNS queries (`ProcDnsProcessLookup`): query source `127.0.0.1:<port>` → `/proc/net/udp` inode → pid via the shared fd scanner. Under resolved every query arrives from `systemd-resolved` (like `mDNSResponder` on macOS); real attribution comes with the BPF helper (OpenSnitch does the same).

## 5. Service and install

`/etc/systemd/system/axiomd.service` written by `axiomd --install-service` (run via pkexec):

```ini
[Unit]  Description=Axiom firewall daemon  After=network-pre.target nss-lookup.target  Wants=network-pre.target
[Service] Type=notify  NotifyAccess=main  ExecStart=/usr/libexec/axiom/axiomd  Environment=AXIOM_SERVICE=1
Restart=on-failure  RestartSec=10  RuntimeDirectory=axiom  RuntimeDirectoryMode=0755  StateDirectory=axiom  StateDirectoryMode=0700
LogsDirectory=axiom  CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_KILL CAP_SYS_RESOURCE
ProtectSystem=strict  ReadWritePaths=/var/lib/axiom /run/axiom /sys/fs/cgroup /etc/resolv.conf  ProtectHome=read-only  NoNewPrivileges=yes  PrivateTmp=yes
[Install] WantedBy=multi-user.target
```

`Type=notify` needs `sd_notify` — implement as a 20-line Unix-datagram write to `$NOTIFY_SOCKET` in `Axiom.Infrastructure.Linux/Systemd/SdNotify.cs` (no native dependency); use `Type=simple` until then. `CAP_SYS_ADMIN` is needed to write `cgroup.procs` of foreign cgroups and attach BPF; keep the list, drop `ProtectHome` only if agent-protection needs home access. Install dir `/usr/libexec/axiom` (root 0755, audited by `PrivilegedHelperLayout`, upgrade = staging dir + rename, exactly §5.3). Uninstall: `systemctl disable --now`, remove unit, dispatcher script, polkit action, restore DNS, delete `/usr/libexec/axiom`, flush `table inet axiom`. Auth table of §5.4 carries over with uid floor 1000 and groups `sudo`/`wheel`. Desktop prompt: `pkexec` with `/usr/share/polkit-1/actions/com.axiom.firewall.policy` (`auth_admin_keep`, `org.freedesktop.policykit.exec.path=/usr/libexec/axiom/axiomd`); the first install (binary not yet in `/usr/libexec`) runs `pkexec <publish>/axiomd --install-service` from the package postinst or from the app with a generic prompt.

## 6. Desktop host (`Axiom.Desktop.Avalonia.Linux`)

Same `Program.cs`/`App.axaml.cs` shape as macOS; `UsePlatformDetect()` (X11 today, Wayland backend when Avalonia 12 ships it; under Wayland sessions X11 apps run through XWayland). Services: `LinuxSingleInstance` (moved), `XdgAutostartService`, `PortalThemeService` (D-Bus), `SecretServiceApiKeyProtector` (`ISecretKeyStore` fallback to `~/.config/axiom/secret.key` 0600), `PkexecProtectionSetup` (replaces `MacProtectionSetup`/osascript), `ProcessActions` (`kill`, `xdg-open`), `TrayIcon` optional: detect `org.kde.StatusNotifierWatcher` on the session bus and fall back to a window-only mode with an in-app banner ("install the AppIndicator extension for a tray icon" on GNOME). Required runtime libs: `libX11`, `libICE`, `libSM`, `fontconfig`, `libdbus-1` (all present here). `PlatformText` gains Linux wording (`systemd service`, `nftables rules`).

## 7. Packaging

| Format | Use | Note |
|---|---|---|
| `.deb` / `.rpm` (nfpm, `scripts/linux/package.sh <rid>`) | primary; ships `/opt/axiom` (desktop, self-contained) + `/usr/libexec/axiom` (daemon) + unit + polkit + dispatcher; postinst runs `axiomd --install-service` | the only format that can install a root daemon cleanly |
| AppImage | desktop app only, for distros without a package; prompts to install the daemon package | daemon cannot live in the AppImage |
| Flatpak | **not viable for the daemon** (sandbox, no system units); desktop-only Flatpak could talk to a separately installed daemon via `/run/axiom/axiom.sock` with `--filesystem=/run/axiom` — defer | document in INSTALL.md |

## 8. Phases

| Phase | Tasks | Size |
|---|---|---|
| **P0 decisions** | Accept §3 decision; confirm minimum kernel 5.13 (`socket cgroupv2`, 2021) and nft ≥ 1.0.3 (`cgroupsv2` set type); choose `/usr/libexec/axiom` vs `/opt/axiom`; uid floor 1000; `reject with tcp reset` vs `drop` default | 1 d |
| **P1 Unix extraction** | Create `src/Axiom.Infrastructure.Unix` + tests; move the 22 files of §2 (git mv, namespace change); parametrise `PeerAuthorization`/`UnixServicePaths`; `AxiomPaths.RuntimeDirectory`; RID-based project selection in `Axiom.Service.csproj`; `ServicePlatform.{MacOS,Linux}.cs`; macOS build + 152 Infrastructure tests still green | 3 d |
| **P2 enforcement spike → adapter** | `NftFirewallPolicyAdapter` + `rules.nft` generator + `CgroupPlacer` + proc-connector watcher; semantic tests fed by `macos/Tests/fixtures/rules-cases.json`; verify `cgroupsv2` sets, inbound hook, IPv6, UDP, `nft -f` atomic replace, dead-cgroup pruning on this box with the spike's `systemd-run` pattern | 5 d |
| **P2b BPF helper** (parallel, optional for v1) | `linux/axiom-bpf/` C + libbpf, `connect4/6`+`sock_ops`, NDJSON client of `/run/axiom/filter.sock`; BTF check in `--doctor` | 6 d |
| **P3 daemon** | `ProcNetConnectionSource`, `LinuxProcessIdentityResolver`, `LinuxDnsConfigurator` + NM dispatcher, `SystemdServiceInstaller`, `SdNotify`, `LinuxDoctor`, `--restore-dns`; end-to-end on this box: install, block `curl` from a user scope, Privacy Shield on/off with resolved | 6 d |
| **P4 desktop** | `Axiom.Desktop.Avalonia.Linux` + the §6 services + tests mirroring `Axiom.Desktop.Avalonia.MacOS.Tests` (35); screenshots per page on GNOME X11 | 5 d |
| **P5 packaging** | nfpm `.deb`/`.rpm`, AppImage, `scripts/linux/deploy-to-vm.sh`, INSTALL.md section, lock-file RID cleanup | 3 d |
| **P6 security review** | repeat the macOS 25-item review on Linux: unit hardening, polkit action scope, `/run/axiom` modes, cgroup writes, nft table ownership (another admin's `nft flush ruleset` kills enforcement → `--doctor` + watcher re-applies), BPF pin dir modes, `PKEXEC_UID` trust | 3 d |

## 9. Risks

- `nft flush ruleset` by firewalld/ufw/docker wipes `table inet axiom`: watch with `nft monitor` and re-apply; `--doctor` FAIL when missing. firewalld (Fedora) also owns its own tables; use a dedicated table and never touch others.
- cgroup-id rules are ephemeral; a race between app exec and set update lets the first connection through (BPF helper closes it; document like the macOS UDP caveat).
- Moving pids out of systemd scopes breaks `systemctl --user stop <scope>` and GNOME's app tracking; prefer keying on existing exclusive cgroups, herd only when needed, and never move pids of system services.
- Wayland: Avalonia has no native backend yet; XWayland works but tray/portal behaviour differs per DE.
- GNOME without the AppIndicator extension has no tray; KDE fine.
- Secret Service absent on minimal/Wayland-sway setups → file fallback must be first-class.
- Distros without resolved and without NM (Arch + iwd/dhcpcd) hit the `/etc/resolv.conf` path, which other daemons may rewrite.

## 10. Testable here vs VM matrix

| On this box (Ubuntu 24.04, GNOME X11, resolved + NM, sudo) | Needs VM / distro matrix |
|---|---|
| All of P1–P3 end to end (spike already run), `.deb` install, polkit prompt, GNOME X11 desktop, portal theme, Secret Service, autostart | Fedora 42 (firewalld coexistence, `.rpm`, SELinux labels for `/usr/libexec/axiom` and `/run/axiom`), Arch (no resolved/NM variant, `wheel` group), KDE Plasma (native SNI tray, Wayland), GNOME Wayland (XWayland + tray extension), kernel 5.13/6.1 LTS minimum checks, BTF presence for P2b, upgrade-in-place across versions |

## 11. Revalidated against 7a48bdf (buba/macos = upstream e45f880, 0.13.0 + perf audit)

The plan above was drafted against 54ecacc (pre-0.11). Between 54ecacc and 7a48bdf upstream landed 165 commits (0.11.0 network recovery, 0.12.0 recovery hardening + service relocation, 0.13.0 agent enforcement + UI overhaul, the perf audit) and the macOS port absorbed them. Every assumption that changed, and the decision taken for Linux:

| # | Plan assumption (§) | What the tree looks like now | Decision for Linux |
|---|---|---|---|
| 1 | §1/§2: the Linux daemon only needs `IFirewallPolicyAdapter`, `IConnectionSnapshotSource`, `IPrivacyDnsPlatform`, `IIpcTransport` | Upstream 0.11–0.12 added **service-owned network recovery**: `NetworkRecoveryController`/`NetworkRecoveryWorker` (`src/Axiom.Service`), `NetworkRecoveryCommand` (`axiomd --recover-network [--apply]`), the `network-recovery.txt` baseline (`NetworkRecoverySnapshotStore`) and two new platform contracts the daemon must provide: `INetworkRecoveryDnsAdapter` (`src/Axiom.Contracts/NetworkRecovery`: `CaptureDns`, `ApplyDns`, `FlushDnsCache`, `AnyAdapterUsesLoopbackDns`; DNS verify is **order-sensitive** since 0.12.0) and `IOwnedRuleRecoveryAdapter` (`src/Axiom.Core/Firewall`: `InspectOwnedRuleAsync`, `RemoveCapturedOwnedRuleAsync`, authorised by the service host or a privileged process, not by the write gate) | Implement both: `LinuxDnsRecoveryAdapter` (adapter = network link, id = SHA-256 UUID of the link name, same scheme as `MacDnsRecoveryAdapter.ServiceId`; Automatic = per-link DNS reverted to the connection's default) and `IOwnedRuleRecoveryAdapter` on the Linux firewall adapter over the daemon's own `managed-rules.json`, exactly like macOS |
| 2 | §2: `ServicePlatform.Unix.cs` has `TryRunCommand` + `ConfigureServices` | The platform class now has 10 hooks that `Program.cs`/`NetworkRecoveryCommand` call: `TryRunCommand`, `HardenMachineState`, `RecoverySnapshotPath`, `HardenRecoverySnapshotLocation`, `CreateDefaultPrivacyDnsPlatform`, `ConfigureServices`, `AttachParentConsole`, `IsAdministrator`, `IsServiceProcessRunning`, `CreateRecoveryAdapters`, `CurrentActor` | Keep one `ServicePlatform.Unix.cs` as the dispatcher; the per-OS bodies live in `Platform/Unix/ServicePlatform.MacOS.cs` and `Platform/Unix/ServicePlatform.Linux.cs` (`partial`), selected at runtime with `OperatingSystem.IsLinux()`. One `net10.0` build serves both; the Windows file and TFM are untouched (the csproj only gains `Platform\Unix\**` in the Windows `Compile Remove` list) |
| 3 | §2: "RID-based project selection in `Axiom.Service.csproj`" | Runtime selection is simpler and lets the Linux and macOS tests run from the same build on this box | The `net10.0` target references `Axiom.Infrastructure.Unix`, `.MacOS` and `.Linux`; no RID conditions |
| 4 | §5: install = copy to `/usr/libexec/axiom`, audit with `PrivilegedHelperLayout` | Upstream 0.12.0 made the Windows installer a **protected-image installer** (`ServiceImageProtection`: Program Files copy, hash verify, wait for pending stop) and the macOS `LaunchdServiceInstaller` mirrors it (stage → chown 0:0 → audit → `bootout` + wait for job removal → atomic replace → SHA-256 `FilesMatch` → record owner uid → bootstrap with retries) | `SystemdServiceInstaller` mirrors the same sequence with systemd verbs (`systemctl stop` + wait for `ActiveState=inactive`, `daemon-reload`, `enable --now`), the same messages and exit codes (5 not root, 2 missing exe, 3 audit failed, 7 hash mismatch, 1 I/O). The generic part of the audit moved to `Axiom.Infrastructure.Unix.Install.ProtectedImageLayout`; `PrivilegedHelperLayout` (macOS) keeps its paths and forwards to it |
| 5 | §2: `MacDataDirectoryPermissions` moves as is | Upstream 0.12.0 added `MachineStateSecurity.HardenProgramData()` after every recovery capture; the macOS port routes it through `ServicePlatform.HardenRecoverySnapshotLocation()` → `HardenMachineState()` and keeps a Unix `MachineStateSecurity.IsReparsePointInPath` for the recovery controller | Moved to `Axiom.Infrastructure.Unix.UnixDataDirectoryPermissions` (same rules: root 0700, files 0600, `filter/` 0755, `filter/rules.json` 0644); Linux `HardenMachineState` applies it to `/var/lib/axiom` on every start |
| 6 | §2: `PeerAuthorization` "parametrise the uid floor 501/1000 and admin group" | The class is still macOS-only (501, nobody = -2, group `admin`); `UnixSocketIpcTransport` re-reads `ProtectionSettings.AllowedUid`/`AllowAdminGroupWrites` per connection; a per-uid cap of 4 connections exists (macOS review #20) | New `UnixAccountRange` (`MacOS`: 501, 4294967294, `admin`; `Linux`: 1000, 65534, `axiom`,`sudo`,`wheel`) passed to `PeerAuthorization.Decide(uid, policy, range)`; the two-argument overloads keep the macOS values so the 155 macOS tests are unchanged. Linux write policy = root, the installing uid, members of `axiom`, `sudo` or `wheel` (see `docs/LINUX_ARCHITECTURE.md` §4) |
| 7 | §2: `UnixFileStat` moves verbatim | It runs BSD `stat -f '%u %g %p %N'` (octal mode); GNU stat needs `-c '%u %g %f %n'` (hex mode) | `UnixFileStat.List(runner, paths, StatFlavor)`; the default stays BSD, Linux code passes `StatFlavor.Gnu` |
| 8 | §2: `InstallOwner` adds `PKEXEC_UID` | Still `SUDO_UID` + owner of `/dev/console` (root-owned on Linux, useless) | `InstallOwner.Resolve(sudoUid, pkexecUid, consoleOwner, range)` in Unix; Linux detection = `SUDO_UID` → `PKEXEC_UID` → none |
| 9 | §1: "MacServicePaths → split: generic `UnixServicePaths` base" | `MacServicePaths` is a sealed record used by `FilterEventServer`, `MacFirewallPolicyAdapter`, `UnixSocketIpcTransport`; it gained `RecoverySnapshotFile` (0.11) | `UnixServicePaths` (record base: data dir, run dir, socket, filter files, DNS backup, recovery snapshot) with `MacServicePaths : UnixServicePaths` and `LinuxServicePaths : UnixServicePaths` (`/var/lib/axiom`, `/run/axiom`, `/var/log/axiom`, unit path). New env overrides for development/non-root runs: `AXIOM_DATA_ROOT` (machine data root, Unix only, honoured by `AxiomPaths.MachineDataDirectory`), `AXIOM_RUNTIME_DIR` (run directory; systemd's own `RUNTIME_DIRECTORY` is honoured too), existing `AXIOM_IPC_SOCKET`, `AXIOM_DATA_DIR` |
| 10 | §3/§8 P2: nftables adapter in this branch | A sibling branch (`buba/linux-enforce`) builds the nftables engine under `src/Axiom.Infrastructure.Linux/Nft` in parallel | This branch ships `Firewall/LinuxFirewallPolicyAdapter.cs` as a **stub**: capability `Unavailable` ("enforcement not available"), desired rules kept in `managed-rules.json` through the shared `ManagedRuleStore`, `IOwnedRuleRecoveryAdapter` implemented over the same record so recovery works before enforcement exists. Nothing is created under `Nft/` |
| 11 | §1: connection source via `/proc/net` + `FlowTable` | `MacConnectionSource` serves flows from `FlowTable` when the filter streams and falls back to libproc; `LibProcSocketScanner.Shared` (2 s shared pass, 500 ms refresh floor) is shared with the DNS attributor (perf audit) | `ProcNetConnectionSource` (socket-table mode only until a Linux filter backend streams flows) over `ProcSocketTable` (same 2 s / 500 ms cache contract), shared with `ProcDnsProcessLookup` |
| 12 | §1: `MacDoctor` → `LinuxDoctor` | `DoctorCheck`/`DoctorTargets` live in the macOS namespace; the doctor gained `--json`, plist/helper/socket/data/DNS/filter checks | `DoctorCheck` moved to `Axiom.Infrastructure.Unix.Diagnostics`; `LinuxDoctor` checks unit state, unit file target, image audit, socket mode, data root mode, DNS backend/links/backup, Privacy Shield, enforcement (WARN: not available in this build) |
| 13 | §5: `Type=notify` "until then `Type=simple`" | — | `SdNotify` (Unix datagram to `$NOTIFY_SOCKET`, `READY=1`/`STOPPING=1`, no native dependency) is in this phase; the unit is `Type=notify` |
| 14 | §5 unit hardening list | 0.13.0 agent enforcement adds nothing the daemon needs beyond the existing adapters; the perf audit added `ConnectionSnapshotCache` (shared) | Unit as in §5 with the capability set documented per capability in `docs/LINUX_ARCHITECTURE.md` §3; `ProtectHome=read-only` kept |
| 15 | §2: `IProcessIdentitySource`/`MacProcessIdentity` move to Unix | `MacProcessIdentity` carries bundle/TeamId/codesign fields | Stays macOS; Linux has `LinuxProcessIdentity` (`/proc/<pid>/exe`, `cmdline`, `stat` ppid chain) and the connection source maps it to `LiveConnection` directly |
| 16 | §2 reuse count "22 of 36" | Counted again on 7a48bdf: 36 files, 20 move or split (`ProcessRunner`, `UnixFileStat`, `UnixGroups`, `UnixPeerCredentials`, `UnixSocketListener`, `PeerAuthorization`, `UnixSocketIpcTransport`, `BoundedLineReader`, `FilterEventServer`, `FilterRulesFile`, `FilterRuleTable`, `FilterStatus`, `FlowEvent`, `FlowTable`, `MacDataDirectoryPermissions`, `PrivilegedHelperLayout` (audit part), `InstallOwner`, `MacServicePaths` (base), `DoctorCheck` (from `MacDoctor.cs`), the managed-rules record of `MacFirewallPolicyAdapter` as `ManagedRuleStore`); 16 stay macOS (`LibProc*`, `ChildSignal`, `Mac*Dns*`, `NetworkSetupParser`, `MacConnectionSource`, `MacProcessIdentity*`, `MacBundleInfo`, `CodeSignatureInfo`, `LaunchdServiceInstaller`, `MacDoctor`, `MacFirewallPolicyAdapter`, `IProcessIdentitySource`) | Done in P1 (this branch) |

P0 decisions fixed here: install dir `/usr/libexec/axiom`; uid floor 1000; write groups `axiom`, `sudo`, `wheel`; `reject with tcp reset` stays the sibling branch's call; minimum kernel/nft as in §8 unchanged.
