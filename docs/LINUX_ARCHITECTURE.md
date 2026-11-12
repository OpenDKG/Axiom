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
| Logs | journald (stderr); `/var/log/axiom` reserved via `LogsDirectory=axiom` | `0755 root` | — |
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

| Peer | Read | Write |
|---|---|---|
| root (uid 0) | yes | yes |
| installing user (`protection.json` `AllowedUid`) | yes | yes |
| member of `axiom`, `sudo` or `wheel` (`AllowAdminGroupWrites`, default on) | yes | yes |
| other uid ≥ 1000 | yes | no (`write denied: not the installing user or an administrator`) |
| system accounts (uid < 1000) and `nobody` (65534) | no | no |

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
only), DNS backend and per-link servers, Privacy Shield redirect/backup consistency, IPC owner
(root only), enforcement availability (`nft --version`). Exit 1 when any check is WARN/FAIL.

## 9. Not in this phase

eBPF attribution (the exec-time race stays, §10), polkit action for the desktop app,
`.deb`/`.rpm` packaging, desktop app/autostart/tray, SELinux/AppArmor profiles, `/etc/axiom` config.

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

**Unit capabilities (as installed).** `CAP_NET_ADMIN CAP_NET_RAW` (nft, raw sockets),
`CAP_SYS_ADMIN` (`cgroup.procs` of foreign cgroups), `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`
(`/proc/<pid>/{exe,fd}` of other users), `CAP_DAC_OVERRIDE` (resolv.conf / resolved runtime
files), `CAP_CHOWN CAP_FOWNER` (0700/0600 enforcement), `CAP_KILL`, `CAP_NET_BIND_SERVICE`
(Privacy Shield resolver on 127.0.0.1:53 — missing in P1, found by the e2e run). `ProtectSystem=strict`
with `ReadWritePaths=/var/lib/axiom /run/axiom /sys/fs/cgroup /etc/resolv.conf /run/systemd/resolve
/run/NetworkManager`, `ProtectControlGroups=no` (the daemon writes cgroups), `NoNewPrivileges=yes`.
Child processes get `NOTIFY_SOCKET` stripped: `resolvectl` otherwise reports `EXIT_STATUS=` to
systemd, which logs "reception only permitted for main PID" every probe.

**Write gate.** `rule.apply/remove/verify` are listed in `capabilities` and accepted only while
`FirewallWriteGate.IsOpen` — i.e. after `protection.enable` (Axiom Shield consent persisted in
`/var/lib/axiom/protection.json`), exactly as on Windows/macOS; before that `firewallWrites` is
`false` and the commands are absent from the list.

**Doctor.** `enforcement` is PASS when the daemon is active and `table inet axiom` is present
(`nftables v1.0.9; table inet axiom generation N is in force`), FAIL when the daemon runs without
the table, WARN when `nft` is missing.
