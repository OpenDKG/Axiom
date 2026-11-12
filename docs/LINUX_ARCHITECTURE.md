# Axiom on Linux — architecture (contract + as built)

Status: phase P3 (daemon with nftables enforcement, proven end to end as root on this box —
`LINUX_TEST_REPORT.md`). §7 below describes the P1 stub for history; §10 is the as-built P3 wiring.
Companion documents: `LINUX_PORT_PLAN.md` (plan and revalidation), `LINUX_ENFORCEMENT.md` (the
engine), `LINUX_TEST_REPORT.md` (evidence), `LINUX_PORT_REPORT.md` (maintainer summary),
`MACOS_ARCHITECTURE.md` (the sibling port this one mirrors).

## 1. Project layout

| Project | Role | Platform guard |
|---|---|---|
| `Axiom.Infrastructure.Unix` | Code shared by macOS and Linux: Unix-socket IPC transport + peer authorization, `ProcessRunner`, `UnixFileStat` (BSD + GNU dialects), `UnixGroups`, `UnixPeerCredentials` (`getpeereid` / `SO_PEERCRED`), filter NDJSON contract (`FilterEventServer`, `FilterRulesFile`, `FilterRuleTable`, `FlowEvent`), `FlowTable`, `ManagedRuleStore`, `UnixDataDirectoryPermissions`, `ProtectedImageLayout`, `InstallOwner`, `DoctorCheck`, `EndpointText`, `UnixServicePaths` | none (`OperatingSystem.IsWindows()` checks only where file modes are set) |
| `Axiom.Infrastructure.MacOS` | macOS-only: launchd, libproc, networksetup/scutil, codesign, system extension, Keychain. `MacServicePaths : UnixServicePaths`, `PrivilegedHelperLayout` forwards to `ProtectedImageLayout` | `[SupportedOSPlatform("macos")]` as before |
| `Axiom.Infrastructure.Linux` | Linux-only: `LinuxServicePaths`, systemd (`SystemdUnit`, `SdNotify`, `SystemdServiceInstaller`), `/proc` monitoring, `/proc` process identity, DNS backends + configurator + recovery adapter, `LinuxDoctor`, `LinuxFirewallPolicyAdapter` (stub) | `OperatingSystem.IsLinux()` at the seams; pure parsers are platform-neutral so tests run anywhere |
| `Axiom.Service` (net10.0) | `ServicePlatform.Unix.cs` forwards to `LinuxServicePlatform` (`ServicePlatform.Linux.cs`) when `OperatingSystem.IsLinux()`; macOS branch unchanged; `ServicePlatform.Windows.cs` untouched. `SystemdReadyNotifier` hosted service sends `READY=1`/`STOPPING=1` | — |

Public API of the macOS project is preserved (155 tests unchanged). Nothing under
`Axiom.Infrastructure.Unix` references `IsMacOS`, libproc, networksetup, launchctl, `/Library`,
scutil or codesign.

## 2. Filesystem contract

| Purpose | Path | Mode / owner | Override |
|---|---|---|---|
| Machine state (database, rules, shield, privacy, `network-recovery.txt`, `protection.json`) | `/var/lib/axiom` (`StateDirectory=axiom`) | `0700 root`, files `0600` | `AXIOM_DATA_ROOT` (Unix only; Windows ignores) |
| Runtime: IPC socket | `/run/axiom/axiom.sock` (`RuntimeDirectory=axiom`) | dir `0755 root`, socket `0666` — access is decided per peer uid, not by the socket mode | `AXIOM_RUNTIME_DIR`, `AXIOM_IPC_SOCKET` |
| Filter socket (nftables engine, later) | `$RuntimeDirectory/filter.sock` | — | `AXIOM_FILTER_SOCKET` |
| Logs | journald (stderr; readable by root and the `adm`/`systemd-journal` groups per systemd policy); `/var/log/axiom` via `LogsDirectory=axiom` `LogsDirectoryMode=0700` — nothing is written there today, but anything that appears is tightened to `0700` dir / `0600` files by the installer, at every daemon start and checked by `--doctor` (review Medium #5) | `0700 root`, files `0600` | — |
| Protected image | `/usr/libexec/axiom` (`axiomd` + publish tree) | dirs `0755`, files `0644`, executables `0755`, all `root:root` | — |
| Unit | `/etc/systemd/system/axiomd.service` | `0644 root` | — |
| `/etc/axiom` | optional, not used in this phase | — | — |
| Build/dev only | `AXIOM_DATA_DIR` (per-user dir, pre-existing) | — | — |

`AxiomPaths.MachineDataDirectoryFor(platform, commonApplicationData, override)` is the pure rule;
`AxiomPaths.MachineDataDirectory` reads `AXIOM_DATA_ROOT`. The service enforces `0700/0600` on
its data root at start (`LinuxServicePlatform.HardenMachineState`, root only) and after the
recovery snapshot is written (`HardenRecoverySnapshotLocation`), mirroring the ProgramData ACL
hardening on Windows.

## 3. Service lifecycle (systemd)

`axiomd --install-service [--dry-run]` (`SystemdServiceInstaller`) runs the same steps as the
launchd installer, with the same messages:

1. copy the publish tree to a staging directory next to `/usr/libexec/axiom`, `chown -R 0:0`,
   set modes; audit with `stat -c %u %g %f %n` (`ProtectedImageLayout.Audit`) — refuse if any
   entry is not root-owned/read-only;
2. `systemctl stop axiomd.service`, poll `is-active` until it is neither `active` nor
   `deactivating` (pending-stop wait, ≤15 s);
3. swap the image in (rename), audit again, compare SHA-256 of the running installer binary
   with the installed `axiomd` (`ProtectedImageLayout.FilesMatch`);
4. create `/var/lib/axiom` `0700`, record the installing user (`SUDO_UID` / `PKEXEC_UID`,
   uid ≥ 1000) as IPC owner in `protection.json`;
5. write the unit (0644), `systemctl daemon-reload`, `systemctl enable --now axiomd.service`
   with up to 8 retries 2 s apart (the previous instance may still be restoring DNS).

`--uninstall-service [--dry-run]`: `systemctl disable --now`, remove the unit, `daemon-reload`,
restore Privacy Shield DNS from the backup if present, remove the image; the data directory is kept.
`--dry-run` prints the plan and the unit text and needs no root.

Unit (`SystemdUnit.Build`), every directive with its reason in the generated file:

```
[Service]
Type=notify              ; READY=1 after the IPC socket listens, STOPPING=1 on shutdown
NotifyAccess=main
ExecStart=/usr/libexec/axiom/axiomd
Restart=on-failure
RestartSec=10
RuntimeDirectory=axiom   ; /run/axiom, recreated on each start
StateDirectory=axiom     ; /var/lib/axiom, StateDirectoryMode=0700
LogsDirectory=axiom
Environment=AXIOM_SERVICE=1
ProtectSystem=strict
ReadWritePaths=/var/lib/axiom /run/axiom /sys/fs/cgroup /etc/resolv.conf /run/systemd/resolve /run/NetworkManager
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
  ; NET_ADMIN/NET_RAW: nftables + sockets; SYS_ADMIN: cgroup attribution; SYS_PTRACE +
  ; DAC_READ_SEARCH: /proc/<pid>/{exe,fd} of other users; DAC_OVERRIDE: resolv.conf, resolved runtime files
```

`SdNotify` writes the datagram to `$NOTIFY_SOCKET` (abstract `@` names supported) with plain
`System.Net.Sockets` — no native dependency.

## 4. IPC

Unchanged protocol: newline-delimited JSON envelopes (`version`, `id`, `type`, `payload`),
`IpcRequestDispatcher` from `Axiom.Service.Hosting`, `UnixSocketIpcTransport` from the Unix
project. The listener resolves the peer with `SO_PEERCRED` and asks `PeerAuthorization.Decide`
with `UnixAccountRange.Linux`:

Every IPC command belongs to one of three classes (`IpcCommandAccess`, shared with macOS): **public
reads** (`serviceHealth`, `capabilities` — redacted: no machine-wide counters beyond the health
summary), **private reads** (`snapshot`, `liveEvents`, `history.query`, `throughput.history`,
`diagnostics.export`, `privacy.status`, `rules.query`, `rule.verify`, `protection.status`, …:
anything that discloses machine-wide activity) and **writes** (`rule.apply/remove`,
`privacy.configure`, `protection.*`, `networkRecovery.restore`, …). The decision is the pure
`PeerAuthorization.Decide(uid, policy, UnixAccountRange.Linux)` — the same function and the same
policy flag as macOS (review 2026-11-12 P0 #1):

| Peer (SO_PEERCRED uid) | Public read | Private read | Write | Reason string |
|---|---|---|---|---|
| root (uid 0) | yes | yes | yes | `root` |
| installing user (`protection.json` `AllowedUid`) | yes | yes | yes | `installing user` |
| member of `axiom`, `sudo` or `wheel` **and** `AllowAdminGroupWrites` (default on, same flag as macOS) | yes | yes | yes | `admin group member (AllowAdminGroupWrites)` |
| other uid ≥ 1000 | yes | **no** (`unauthorized`) | **no** (`unauthorized`) | `console user` — "private read/write commands are not allowed for this caller" |
| system accounts (uid < 1000), `nobody` (65534) | no (connection closed) | no | no | `system account` / `nobody` |
| peer uid unreadable | no | no | no | `unknown peer` |

Every denial is one journal line: `Denied '<command>' for uid:<n>: private read commands are not
allowed for this caller.` The transport also caps connections per uid (4). Tests:
`tests/Axiom.Infrastructure.Unix.Tests/LinuxPeerAuthorizationTests.cs` (pure table) and
`tests/Axiom.Infrastructure.Linux.Tests/LinuxSocketIpcTests.cs` (real socket; the second-uid case
runs when `AXIOM_TEST_SECOND_USER` names an account reachable through `sudo -n -u`).

`scripts/linux/axipc.py <command> [json]` is a dependency-free client (`AXIOM_IPC_SOCKET` or
`/run/axiom/axiom.sock`).

## 5. DNS (Privacy Shield + network recovery)

`LinuxDnsBackendDetector.Decide(resolvConfTarget, resolvectlWorks, networkManagerRunning)`:

1. `/etc/resolv.conf` is a symlink into `systemd/resolve` **and** `resolvectl dns` works →
   **systemd-resolved**: per link `resolvectl dns <link> 127.0.0.1` + `resolvectl domain <link> ~.`
   (routing domain so every query goes to the shield); restore = saved servers/domains or
   `resolvectl revert`; cache flush `resolvectl flush-caches`.
2. else `nmcli -g RUNNING general` = running → **NetworkManager**: per active connection (loopback,
   bridge, tun, veth, dummy, wireguard skipped) `nmcli connection modify <uuid> ipv4.dns 127.0.0.1
   ipv4.ignore-auto-dns yes …` + `nmcli device reapply`; restore = saved explicit servers with
   `ignore-auto-dns no`.
3. else **/etc/resolv.conf**: atomic rewrite with `nameserver 127.0.0.1`; the exact previous text is
   stored in the backup and written back verbatim on restore.

`LinuxDnsConfigurator` writes `privacy-shield-dns-backup.json` (0600) *before* changing anything;
`RestoreIfNeeded()` on start and stop repairs every link that still points only at loopback and
deletes the backup once nothing is redirected. `DiscoverUpstreams()` returns live non-loopback
resolvers, or the saved ones while redirected. Only port 53 can be the system resolver on Linux;
other ports leave DNS untouched with a warning.

`LinuxDnsRecoveryAdapter : INetworkRecoveryDnsAdapter` (service-owned recovery, upstream 0.11+):
a "network adapter" is a resolved link / NetworkManager connection / the resolv.conf pseudo-link,
identified by a stable UUIDv5-style hash of `backend:name`; explicit servers → `Static`, none →
`Automatic`. `ApplyDns` validates ids and address families, is idempotent (order-sensitive
comparison like Windows/macOS), reads back and throws `NetworkRecoveryPlatformException`
(`dns_adapter_invalid`, `dns_state_invalid`, `dns_apply_failed`, `dns_verify_failed`) on failure.
`axiomd --recover-network` uses it through `NetworkRecoveryController` unchanged.

## 6. Monitoring and attribution

`ProcNetTable` parses `/proc/net/{tcp,tcp6,udp,udp6}` (hex host-order addresses, v4-mapped v6
folded to v4, closed rows dropped). `ProcSocketScanner.Shared` joins them with `socket:[inode]`
links under `/proc/<pid>/fd` (2 s lifetime, 500 ms refresh floor, like `LibProcSocketScanner`).
`ProcProcessIdentityResolver` reads `exe`, `comm`, `cmdline`, `stat` (ppid, with spaces-in-comm
parsing) and `status` (uid) and builds the parent chain. `LinuxConnectionSource :
IConnectionSnapshotSource` (`sourceName = "/proc socket tables"`) emits `LiveConnection`s with
direction from TCP state, first-seen tracking and explicit limitations (non-root attribution
limited to own uid, no byte counters, no sub-poll connections, UDP peers unknown).
`LinuxDnsProcessLookup : IDnsProcessLookup` attributes resolver queries by local endpoint for
`ProcessDnsAppAttributor`. Flow events via `FlowTable` take over once the nftables engine streams
them.

## 7. Firewall (stub in this phase)

`LinuxFirewallPolicyAdapter : IFirewallPolicyAdapter, IOwnedRuleRecoveryAdapter`
(`src/Axiom.Infrastructure.Linux/Firewall/`): capabilities report
`FirewallCapabilityStatus.Unavailable` with the reason "firewall enforcement is not available on
Linux in this build (nftables engine pending)"; rules are validated, gated by `FirewallWriteGate`,
persisted in `filter/managed-rules.json` via the shared `ManagedRuleStore` with
`RuleState.Desired` and `ErrorCode = enforcement.unavailable`; verify reports `PresentInOs = false`
with a note; owned-rule inspection/removal works on the store so network recovery and the UI see
a consistent, honest state. The nftables engine replaces this class without touching callers.

## 8. Doctor

`axiomd --doctor [--json]` (`LinuxDoctor`): unit present + `ExecStart` matches the image, service
active/enabled, image audit (root-owned, read-only), socket owner/mode, data directory 0700 (root
only), **log directory** (`/var/log/axiom` root 0700 and every file 0600 when it exists; "journal
only" otherwise), DNS backend and per-link servers, Privacy Shield redirect/backup consistency, IPC
owner (root only), enforcement (`nft --version`; as root also that `table inet axiom` is in force)
and the **bpf layer** (bpftool + the four pins at `/sys/fs/bpf/axiom`, §12). Exit 1 when any check
is WARN/FAIL.

## 9. Not in this phase

polkit action for the desktop app, `.deb`/`.rpm` packaging, SELinux/AppArmor profiles, `/etc/axiom`
config. (The eBPF layer and the desktop host landed later: §11, §12.)

## 10. As built in P3: the nftables engine inside axiomd

`LinuxFirewallPolicyAdapter` (§7) is gone; `LinuxEnforcement.Create(paths, sink, log)` builds
`NftFirewallPolicyAdapter : IFirewallPolicyAdapter, IOwnedRuleRecoveryAdapter` over the real
`nft` runner and `ProcCgroupFs` (`src/Axiom.Infrastructure.Linux/Nft/`, `LINUX_ENFORCEMENT.md`).

**Hosted service.** `NftEnforcementWorker` (`src/Axiom.Service/Platform/`, Linux only, in the
Windows TFM `Compile Remove` list) runs `NftEnforcementSupervisor.RunAsync`:

1. *publish at start* — `table inet axiom` from `filter/managed-rules.json` (`Published table inet
   axiom generation N (a applied, r rejected)` in the journal); rules survive daemon restarts and
   upgrades because the store, not the kernel, is the source of truth;
2. *attribution loop* (1 s) — `AppCgroupManager.Attribute()` walks `/proc`, matches
   `/proc/<pid>/exe` against the app paths of enabled rules and writes the pid into
   `axiom.slice/a-<hash>/cgroup.procs`; only moves out of `system.slice/*.service` and failures
   are logged (user-scope moves are routine); unused app cgroups are removed;
3. *ruleset watcher* (10 s) — `nft -j list table inet axiom`; when the table is gone (another
   admin's `nft flush ruleset`) it republishes (`generation` increments) and logs it;
4. *trace monitor* — `nft monitor trace` child (restarted on exit), `NftTraceParser` joins
   `packet:`/`rule … (verdict …)` records of the block rules (`meta nftrace set 1`) into NDJSON
   flow events; `FilterEventPipe` feeds them to the shared `FilterEventServer`/`FlowTable`;
5. *teardown* on stop — herded pids go back to their origin cgroups, app cgroups and the table
   are deleted; `--uninstall-service` repeats the table + `axiom.slice` removal belt-and-braces.

**Rule lifecycle (review 2026-11-12 P0 #2/#3, High #4).** `rule.apply` stores the rule
**Pending**, publishes the whole table as one `nft -f` batch and then reads it back with
`nft -j list table inet axiom`. The rule becomes **Applied** only when the batch succeeded **and**
the readback carries the published generation comment (`axiom generation N`) **and** the rule's own
comment (`axiom:<id>:n`) **and** the app cgroup `axiom.slice/a-<hash>` exists **and** no live pid of
that app failed to be herded; otherwise it stays Pending with the reason (`nft.readback_mismatch`,
`nft.cgroup_missing`, `nft.attribution_failed`) or is **Failed** when the compiler refused it
(`rule.invalid` / `nft.rule_rejected`, e.g. a hostname in `remoteAddresses`). `rule.verify` takes
`presentInOs`, `effectiveAction` and `enforcementVerified` from the readback alone, never from the
store. `rules.query → capabilities.filterEnforcement` is the honest boundary report:
`{state, connected, publishedGeneration, ackedGeneration, lastSeenUtc, lastAckUtc, generation,
appliedRuleCount, rejectedRules, fileError}` with `state` **verified** (readback matches the
published generation), **pending** (published, readback not yet seen), **degraded** (the table
vanished — `nft flush ruleset` by another admin — or `nft` cannot be read; `connected:false`,
`ackedGeneration:null`) or **unavailable** (`nft` missing / torn down). `firewallServiceRunning`
is live. The watcher degrades the report *immediately* when the table disappears, logs
`table inet axiom disappeared (generation N was published); enforcement degraded; republishing.`,
republishes and returns to verified (`Republished table inet axiom generation N+1; enforcement
verified.`). `capabilities.firewall.limitations` always lists the ~1 s exec race of the attribution
loop and, when the BPF layer is inactive, that nftables is the only boundary. Tests:
`tests/Axiom.Infrastructure.Linux.Nft.Tests/NftLifecycleTests.cs`.

**Event flow.** Block verdict → trace record → `FlowObservation{verdict:"block", ruleId}` →
`LinuxConnectionSource.BlockedFlows` lists it next to the `/proc` sockets (`state: Blocked`,
`ruleStatus: blockedByOwnedRule`, `quality: observed`, pid 0 when the rejected SYN's socket is
already gone — `DescribeRuleApp` falls back to the rule's app path) → `snapshot` IPC → history
database. Allowed flows are not traced (counters only). `rules.query` reports
`filterEnforcement {generation, appliedRuleCount, rejectedRules[]}`; a rule whose live process
could not be moved is listed as rejected with the reason; `rule.verify` adds "table inet axiom
generation N, 3 nft rule(s), M packet(s) matched".

**Exec-time race.** A process is herded on the next loop pass (≤1 s after exec) and nftables
matches the socket's cgroup *at socket creation*: a `curl` that connects within its first second
is not blocked, and connections a process opened before it was herded stay open. Long-lived
processes and every later connection are blocked with an immediate TCP reset (`curl: (7) … after
0 ms`). Same class of caveat as the macOS UDP note; closing it needs the eBPF `cgroup/connect4`
helper (P2b) or a proc-connector exec watcher.

**Supervisor lifetime (PR #276 review, LNX-2).** `RunAsync` = `try { ReconcileOrphansAsync; publish;
StartLayerAsync; loops (attribution 1 s, watcher, nft trace, BPF events) } finally { TeardownAsync }`.
A loop fault cancels the sibling loops (linked token), is logged first, the teardown runs, the fault is
rethrown and `NftEnforcementWorker` exits 70 for `Restart=on-failure`. Teardown steps are independent and
bounded (8 s each, under `TimeoutStopSec=30`): BPF detach/unpin, `delete table inet axiom`, cgroup
release; errors aggregated in one journal line. Startup reconciliation logs and repairs what a killed
instance left (table, `axiom.slice` cgroups, attached/pinned `axiom_*` programs) — see
LINUX_ENFORCEMENT.md §8. Proven live with `systemctl kill -s KILL`, `systemctl stop/start` and a package
upgrade (LINUX_TEST_REPORT.md, "PR #276 review").

**Capabilities, justified one by one** (bounding set; the daemon runs as root inside it):

| Capability | Why | Without it |
|---|---|---|
| `CAP_NET_ADMIN` | nftables batches (`table inet axiom`), `nft monitor trace`, netlink | no enforcement at all |
| `CAP_SYS_ADMIN` | write `cgroup.procs` of foreign cgroups (herding), attach BPF programs at the cgroup root (`BPF_PROG_ATTACH` on a cgroup requires it), bpffs pins | no attribution, no BPF layer |
| `CAP_BPF` | `bpf()` program load and map create/update/delete/dump | BPF layer inactive (nft-only, reported) |
| `CAP_PERFMON` | the CO-RE exe lookup (`bpf_get_current_task_btf`, `bpf_probe_read_kernel`) is gated on `perfmon_capable()` | verifier rejects the programs → nft-only |
| `CAP_NET_BIND_SERVICE` | Privacy Shield resolver on 127.0.0.1:53 (found missing by the P3 e2e) | `privacy.configure` fails with EACCES |
| `CAP_NET_RAW` | reserved for raw/packet sockets of a future helper (unit comment); not re-audited in this pass — candidate for removal once confirmed unused | to be confirmed |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | `/proc/<pid>/{exe,fd}` of other users (attribution, socket owners) | other users' processes unattributed |
| `CAP_DAC_OVERRIDE` | `/etc/resolv.conf`, resolved runtime files | DNS backends fail |
| `CAP_CHOWN`, `CAP_FOWNER` | enforce 0700/0600 ownership on data/log files | permission repair fails |
| `CAP_KILL` | ending a blocked process of another user on request | that action fails |

**Unit capabilities (as installed).** `CAP_NET_ADMIN CAP_NET_RAW` (nft, raw sockets),
`CAP_SYS_ADMIN` (`cgroup.procs` of foreign cgroups), `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`
(`/proc/<pid>/{exe,fd}` of other users), `CAP_DAC_OVERRIDE` (resolv.conf / resolved runtime
files), `CAP_CHOWN CAP_FOWNER` (0700/0600 enforcement), `CAP_KILL`, `CAP_NET_BIND_SERVICE`
(Privacy Shield resolver on 127.0.0.1:53 — missing in P1, found by the e2e run). `ProtectSystem=strict`
with `ReadWritePaths=/var/lib/axiom /run/axiom /sys/fs/cgroup /sys/fs/bpf /etc/resolv.conf
/run/systemd/resolve /run/NetworkManager`, `ProtectControlGroups=no` (the daemon writes cgroups),
`NoNewPrivileges=yes`, `CAP_BPF CAP_PERFMON` for the BPF layer. `ProtectKernelTunables=no` with the
equivalent `ReadOnlyPaths=-/proc/sys … -/sys/kernel …` spelled out by hand: `ProtectKernelTunables=yes`
mounts `/sys/fs/bpf` read-only and neither `ReadWritePaths` nor `BindPaths` can undo it (systemd 255:
`failed to mkdir /sys/fs/bpf/axiom/axiom_connect4: -EROFS`), which kept the BPF layer from pinning.
Child processes get `NOTIFY_SOCKET` stripped: `resolvectl` otherwise reports `EXIT_STATUS=` to
systemd, which logs "reception only permitted for main PID" every probe.

**Write gate.** `rule.apply/remove/verify` are listed in `capabilities` and accepted only while
`FirewallWriteGate.IsOpen` — i.e. after `protection.enable` (Axiom Shield consent persisted in
`/var/lib/axiom/protection.json`), exactly as on Windows/macOS; before that `firewallWrites` is
`false` and the commands are absent from the list.

**Doctor.** `enforcement` is PASS when the daemon is active and `table inet axiom` is present
(`nftables v1.0.9; table inet axiom generation N is in force`), FAIL when the daemon runs without
the table, WARN when `nft` is missing.

## 11. As built in P4: the desktop host (`src/Axiom.Desktop.Avalonia.Linux`)

Same `Program.cs`/`App.axaml.cs` shape as the macOS host, `UsePlatformDetect()` (X11 on this box;
Wayland sessions run it through XWayland). The window process is unprivileged and never touches
nftables, DNS or `/var/lib/axiom`: everything machine-wide goes over the IPC socket to `axiomd`.
The bundle is `dotnet publish src/Axiom.Desktop.Avalonia.Linux -r linux-x64 --self-contained` plus a
copy of the daemon publish tree at `<bundle>/axiomd/` (the installer is looked up there).

| Concern | Host service | Mechanism (as built) |
|---|---|---|
| Single instance | `LinuxSingleInstance` (taken in `Main` before Avalonia starts) | `flock` on `$XDG_RUNTIME_DIR/axiom-desktop.lock` + Unix socket `axiom-desktop.sock`; a second launch writes `show` to the socket, logs `Another Axiom instance is running; show signal delivered=True` and exits 0 before any Avalonia object exists (the earlier in-`App` variant crashed with `Dispatcher shut down`) |
| Daemon install / upgrade | `LinuxProtectionSetup` + `ProtectionServiceInstall.InstallAndStartLinuxAsync` | Detects the daemon through the IPC socket, the unit file and `systemctl is-active` (`Running` / `InstalledNotResponding` / `NotInstalled`). On `NotInstalled` it asks once at startup (declining writes `~/.local/state/axiom/daemon-install-declined`); the tray menu and the Shield page re-offer it. Install runs `pkexec <bundle>/axiomd/axiomd --install-service`; polkit's agent shows the password prompt, a cancel surfaces as "Administrator approval was cancelled.", a missing `<bundle>/axiomd/axiomd` as "The Axiom daemon was not found at …. Reinstall Axiom.". The desktop never starts, stops or restarts the unit itself |
| Polkit policy | `packaging/linux/com.axiom.firewall.policy` | Action `com.axiom.firewall.install`, `auth_admin_keep`, `exec.path=/usr/libexec/axiom/axiomd`. Installed by the package to `/usr/share/polkit-1/actions/`; the first install runs the daemon from the bundle, which does not match `exec.path`, so pkexec shows its generic "Authentication is needed to run … as the super user" text (seen in `docs/screenshots/linux/polkit-install.png`); the package postinst avoids that by running the install itself |
| Tray | `StatusNotifierProbe` + Avalonia `TrayIcon` | Probes `org.kde.StatusNotifierWatcher` on the session bus at startup. Present (KDE, GNOME + AppIndicator extension — this box) → tray icon with status / Install / notifications items and close-to-tray; absent (stock GNOME) → no tray, closing the window quits, logged as `[tray] no StatusNotifierWatcher on the session bus; no tray, close = quit` |
| Autostart | `LinuxAutostartService : IAutostartService` | Writes only `~/.config/autostart/com.axiom.firewall.desktop` (`Exec="<bundle>/Axiom" --autostart`, `X-GNOME-Autostart-enabled`, `X-KDE-autostart-after=panel`); unticking deletes the file; reports `path is stale; repair` when the entry points at another bundle; no machine-wide entry |
| Secrets (AI analyst key, reputation key, community token) | `SecretServiceApiKeyProtector : IApiKeyProtector` over `ISecretKeyStore` | Same AES-256-GCM envelope as the macOS Keychain protector (`ss1:` prefix in the settings file). The 256-bit key lives in the Secret Service keyring via `secret-tool` (`service=com.axiom.firewall account=secret-protection-key`, key passed on stdin) when libsecret's CLI is on `PATH`, else in `$XDG_STATE_HOME/axiom/secret-protection-key` (0600 in a 0700 directory; this box has no `secret-tool`, so it used the file). `ChainedSecretKeyStore` reads keyring then file. The UI shows "stored with keyring" and never the key |
| Theme | `LinuxThemeService` | `org.freedesktop.portal.Settings` `color-scheme` (1 dark, 2 light) until the user picks a palette; follows changes |
| DNS adapter list | `LinuxDnsAdapterHelper` | Read-only `resolvectl status` per link; the daemon changes DNS, the desktop only displays it |
| Process actions | `ProcessActions` | SIGTERM then SIGKILL after a grace period, refused for pid 1, root-owned and other users' processes (`pid 12 not ended: RootOwned`); `xdg-open` for paths |
| Restart / shutdown | `AvaloniaShellActions` | Relaunches the executable after a delay so the new process does not meet the old lock |
| Diagnostics | `StartupLog` | `~/.local/state/axiom/desktop.log` (+ stderr); fixed messages and exception text only |

Not in P4: Windows firewall profiles are hidden off Windows (shared `FirewallPageViewModel`),
and there is no Wayland-native backend.

**Package-installed daemon (P5, docs/LINUX_PACKAGING.md).** The `.deb`/`.rpm` installs the bundle
under `/opt/axiom` and its `postinst` runs `/opt/axiom/axiomd/axiomd --install-service` itself, so
the daemon is registered before the first launch. `LinuxDaemonLayout.IsPackageManaged` (executable
under `/opt/axiom`) makes `LinuxProtectionSetup.ShouldOfferInstallAtStartup` false: a package
install never shows the pkexec prompt at startup, whatever the unit state (a missing unit is then a
damaged package, logged as `package-managed install (/opt/axiom); no startup install offer`), while
the Shield page's manual Install/Upgrade stays available and, because the package also installs the
polkit action and the image path matches `exec.path`, shows the Axiom-specific polkit message. The
desktop publish itself now always carries `axiomd/` (`PublishBundledDaemon` target), the desktop
entry and hicolor icons are installed by the package, and the bundle's own copies of the packaging
files are not shipped.

## 12. As built in P2b: the connect-time BPF layer (`src/Axiom.Infrastructure.Linux/Bpf`)

Design and map/event contract: `docs/LINUX_EBPF.md`. Status on the evidence box (2026-11-12): **active and
proven** — journal `BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at /sys/fs/cgroup (multi), pinned
at /sys/fs/bpf/axiom.`; a bare `curl -m 8 https://example.com` run *immediately* after `rule.apply` fails with
`curl: (7) … after 0 ms` (rc 7, ~8 ms) — the ~1 s exec race of the attribution loop is closed for unscoped
outbound block rules, and the rule keeps blocking while `table inet axiom` is deleted and republished
(the verdict comes from the maps, not from nft). `capabilities.firewall.limitations` then names only the
attribution loop ("The BPF layer closes this window for unscoped outbound block rules."); when the layer is
inactive the second limitation names the reason (`BPF layer inactive (<status>): … nftables (socket cgroupv2)
is the only boundary.`), `--doctor` `bpf layer` WARNs and nothing else changes — nftables stays the primary
boundary. Scoped (address/port) and inbound rules are nft-only, so the ~1 s window remains for them.

Verifier facts that cost a round: a `cgroup/connect4` program may read only `user_ip4`, a `connect6` one only
`user_ip6` (`invalid bpf_context access off=8`), so the loopback check and the event copy are specialised per
family at compile time. `bpftool prog loadall` pins by section name (`axiom_connect4` …) and the maps under
`<pin>/maps/`; `bpftool cgroup tree` shows them `multi` at `/sys/fs/cgroup` next to systemd's own
`sd_fw_egress`/`sd_devices` programs. The e2e script (`scripts/linux/bpf/e2e.sh`) counts only its own
program ids, because a running `axiomd` keeps its four programs attached at the root as well.
