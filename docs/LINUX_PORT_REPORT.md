# Axiom for Linux — port report for the maintainer

Date: 2026-11-12. Branch `buba/linux` on top of `buba/macos` (`7a48bdf`, upstream e45f880 / v0.13.0 + perf audit).
Not pushed; local only. Scope: the **root daemon** (`axiomd`) with nftables enforcement, systemd lifecycle,
Privacy Shield DNS on systemd-resolved/NetworkManager/resolv.conf hosts, network recovery, `/proc` monitoring and
`--doctor` — proven end to end as root on an Ubuntu 24.04 box (kernel 7.0, systemd 255, nft 1.0.9). No desktop
app and no packages yet.

Detailed docs in the branch: `docs/LINUX_ARCHITECTURE.md` (contract + as built, §10 for the engine wiring),
`docs/LINUX_ENFORCEMENT.md` (nftables/cgroup engine, decisions, e2e script), `docs/LINUX_TEST_REPORT.md`
(P1 and P3 rows with commands and outputs), `docs/LINUX_PORT_PLAN.md` (plan, revalidation, status table §11.2),
`scripts/linux/axipc.py` (stdlib IPC client), `scripts/linux/nft/e2e.sh` (root engine e2e).

## 1. What was accomplished

- **`Axiom.Infrastructure.Unix`** (new): the 22 Unix-generic files of the macOS infrastructure project (Unix
  socket IPC transport + peer authorization, `ToolProcess`/`ProcessRunner`, filter NDJSON contract + `FlowTable`,
  protected-image layout + audit, data-dir permissions, single instance, managed-rule store) extracted and
  parametrised (`UnixAccountRange` macOS/Linux, `StatFlavor` GNU/BSD). The macOS project depends on it through
  thin facades; its 155 tests pass unchanged.
- **`Axiom.Infrastructure.Linux`** (new): `LinuxServicePaths` (`/usr/libexec/axiom`, `/var/lib/axiom`,
  `/run/axiom/axiom.sock`), `SystemdUnit` + `SystemdServiceInstaller` (`--install-service`/`--uninstall-service`
  with `--dry-run`), `SdNotify` (hand-rolled `Type=notify`), `/proc` connection source + process identity resolver,
  DNS backends (resolved → NetworkManager → resolv.conf, pure detector), DNS configurator with 0600 backup, network
  recovery adapter, `LinuxDoctor`, and the **nftables engine** under `Nft/`: `NftRuleCompiler` (RuleSpec → `table
  inet axiom`, one `socket cgroupv2` rule set per app, generation comments), `NftTable` (atomic `nft -f` replace,
  JSON read-back), `AppCgroupManager` (`axiom.slice/a-<hash>` per app, pid herding via `cgroup.procs`, origin
  tracking for release), `NftTraceMonitor`/`NftTraceParser` (block verdicts → flow events), `NftFirewallPolicyAdapter`
  (`IFirewallPolicyAdapter` + `IOwnedRuleRecoveryAdapter`), `NftEnforcementSupervisor` (publish at start, 1 s
  attribution loop, 10 s ruleset watcher that republishes after `nft flush ruleset`, trace monitor restart, teardown).
- **`axiomd`** on Linux: `Axiom.Service` publishes self-contained `linux-x64`; `ServicePlatform.Linux.cs` wires
  the Linux adapters into the shared host (IPC dispatcher, protection, Privacy Shield, history, recovery) and
  `NftEnforcementWorker` runs the supervisor. Same IPC protocol and command set as Windows/macOS; `axipc.py`
  talks to it with nothing but the standard library.
- **Proven on the box** (`LINUX_TEST_REPORT.md` P3): install → `Type=notify` ready → doctor all PASS →
  `protection.enable` opens the write gate → `rule.apply` Block `/usr/bin/curl` → immediate TCP reset
  (`curl: (7) … after 0 ms`), nft counters, traced block visible in `snapshot` → `rule.remove` releases the
  cgroup → read-only user gets `unauthorized` → Privacy Shield redirects resolved's link DNS to 127.0.0.1
  (`doubleclick.net` NXDOMAIN, `example.com` resolves) and restores → `networkRecovery.restore` restores DNS →
  restart republishes the rule → in-place upgrade keeps the rule → uninstall leaves no unit/image/table/cgroup/
  socket and DNS identical to the baseline.
- Tests: Infrastructure.Unix 22, Infrastructure.Linux 27, Infrastructure.Linux.Nft 54 (fake `nft` runner + fake
  cgroup/proc fs; the same test exe is the root e2e harness). Full solution build with `EnableWindowsTargeting`:
  0 warnings, 0 errors; every other suite unchanged (Core 117/128 is the pre-existing Windows-path baseline).

## 2. What changed in shared code since `7a48bdf`

`git diff --stat 7a48bdf..HEAD -- src/Axiom.Core src/Axiom.Contracts src/Axiom.Service src/Axiom.Service.Hosting
src/Axiom.Presentation src/Axiom.UI.Avalonia` — 11 files, +651/−36, all of it in `Axiom.Contracts` and
`Axiom.Service`; `Axiom.Core`, `Axiom.Service.Hosting`, `Axiom.Presentation`, `Axiom.UI.Avalonia` untouched:

- `Axiom.Contracts/AxiomPaths.cs` (+16/−): `AXIOM_DATA_ROOT` override for the machine data root (Unix only,
  for non-root daemon runs) — Windows paths unchanged.
- `Axiom.Contracts/ToolProcess.cs` (+3): child processes no longer inherit `NOTIFY_SOCKET` (systemd tools
  would otherwise notify systemd on the daemon's behalf). No-op on Windows/macOS.
- `Axiom.Contracts/Properties/AssemblyInfo.cs` (+2): `InternalsVisibleTo` for the Unix tests.
- `Axiom.Service/Axiom.Service.csproj`: RID-based project reference (`linux-*` → `Axiom.Infrastructure.Linux`),
  Linux-only files in the Windows TFM `Compile Remove` list; `packages.lock.json` regenerated for the new
  RID section.
- `Axiom.Service/Platform/ServicePlatform.Linux.cs` (new, 126 lines) + `ServicePlatform.Unix.cs` (+37/−):
  each macOS hook forwards to `LinuxServicePlatform` on Linux; the macOS bodies did not move.
- `Axiom.Service/Platform/SystemdReadyNotifier.cs` (new): hosted service sending `READY=1`/`STOPPING=1`.
- `Axiom.Service/Platform/NftEnforcementWorker.cs` (new): hosted service running the engine supervisor.
- `Axiom.Service/Platform/FilterEventWorker.cs` (+1), `MachineStateSecurity.Unix.cs` (+2/−): Linux branch.

Nothing in the Windows projects (`Axiom.Infrastructure.Windows`, `Axiom.UI`, `Axiom.Desktop`) changed.

## 3. Linux-specific facts the maintainer must know

- **nftables, not pf/WFP.** One `table inet axiom` owned by the daemon (generation comment), chains
  `axiom_out`/`axiom_in` with policy accept, loopback accepted first, then per-app rules
  `meta l4proto tcp socket cgroupv2 level 2 "axiom.slice/a-<hash>" counter meta nftrace set 1 reject with tcp
  reset`, UDP/other `drop`. Nothing else on the host's ruleset is touched; `nft flush ruleset` by another admin is
  detected within 10 s and the table republished.
- **Reject-with-reset vs drop.** TCP blocks answer with a reset: clients fail in 0 ms with ECONNREFUSED instead of
  the macOS/Windows connect timeout. Switching to `drop` for parity is a one-line change in `NftRuleCompiler`.
- **Attribution = cgroups + a race.** Rules are keyed on the app's cgroup; the daemon moves matching pids
  (`/proc/<pid>/exe` == app path) into `axiom.slice/a-<hash>` once a second. nftables classifies a socket by the
  cgroup it was *created* in, so (a) a process that connects within its first second gets that connection through,
  (b) sockets opened before herding stay open, (c) every later socket of the process is blocked. Already-running
  processes are blocked without relaunch. `cgroup.procs` writes need `CAP_SYS_ADMIN`; the eBPF
  `cgroup/connect4` helper (planned P2b) would close the race.
- **systemd unit.** `Type=notify` (hand-rolled sd_notify, no libsystemd), `RuntimeDirectory=axiom`,
  `StateDirectory=axiom` (0700), `ProtectSystem=strict` + explicit `ReadWritePaths` (`/sys/fs/cgroup`,
  `/etc/resolv.conf`, `/run/systemd/resolve`, `/run/NetworkManager`), `ProtectControlGroups=no`,
  `NoNewPrivileges=yes`, `CapabilityBoundingSet` = NET_ADMIN NET_RAW SYS_ADMIN SYS_PTRACE DAC_READ_SEARCH
  DAC_OVERRIDE CHOWN FOWNER KILL **NET_BIND_SERVICE** (the last one was missing until the e2e run: without it even
  root cannot bind 127.0.0.1:53). Children must not inherit `NOTIFY_SOCKET`.
- **IPC.** `/run/axiom/axiom.sock` 0666, peer uid via `SO_PEERCRED`; readers: root and uids ≥ 1000 (nobody
  65534 excluded, refused at accept); writers: root, the installing user (`SUDO_UID`/`PKEXEC_UID` recorded in
  `protection.json`) and members of `axiom`, `sudo` or `wheel`. The firewall write gate is the shared one:
  `rule.*` only after `protection.enable` (Axiom Shield consent).
- **DNS.** systemd-resolved is the common case: the resolved stub (`127.0.0.53`) stays in `/etc/resolv.conf` and
  the Privacy Shield proxy on `127.0.0.1:53` is set per link with `resolvectl dns <link> 127.0.0.1` +
  `resolvectl domain <link> ~.`; restore replays the 0600 backup and must clear the domain with an explicit empty
  argument (bare `resolvectl domain <link>` only prints — fixed). NetworkManager (`nmcli con mod ipv4.dns`) and a
  static `/etc/resolv.conf` (exact previous text restored) are the fallbacks, unit-tested only. The network
  recovery baseline is captured at service start from the same backends.
- **Monitoring.** `/proc/net/{tcp,tcp6,udp,udp6}` joined with `/proc/<pid>/fd` (root sees every user); no byte
  counters, no sub-second connections, UDP peers unknown. Blocked attempts come only from the nft trace of the
  block rules, so `snapshot` shows them with `state: Blocked`, pid 0 when the socket died before the trace was read.
- **Install layout.** `/usr/libexec/axiom` root-owned read-only (audited with `stat -c`, SHA-256 of the installer
  binary vs the installed one), `/etc/systemd/system/axiomd.service` 0644, `/var/lib/axiom` 0700 kept on uninstall
  (as macOS keeps its data root), `/run/axiom` by systemd.
- **No desktop app yet.** Everything is reachable over IPC (`scripts/linux/axipc.py`) and the Avalonia UI projects
  build on Linux, but `Axiom.Desktop.Avalonia.Linux` (tray via StatusNotifierItem — optional on GNOME, portal
  color-scheme, `pkexec` + polkit action for install, autostart `.desktop`) is not started.
- **Packaging not done.** Only `dotnet publish … -r linux-x64 --self-contained` + `--install-service`; `.deb`/`.rpm`
  (nfpm), AppImage, SELinux/AppArmor profiles, firewalld coexistence are open.

## 4. Not done / unverified

- eBPF helper (P2b) — the exec-time race above is the main functional gap versus the macOS content filter.
- Desktop app (P4), packaging (P5), security review (P6) — see `LINUX_PORT_PLAN.md` §11.2.
- Only systemd-resolved was exercised live; NetworkManager and resolv.conf backends, inbound rules and
  address/port-scoped rules on a live kernel, Fedora/SELinux, kernels without `nft_socket`, non-x64.
- `--restore-dns` as a standalone command does not exist on Linux; `--uninstall-service` and
  `networkRecovery.restore` cover the recovery paths that were needed.
- Three defects found by the root e2e and fixed in this branch (`CAP_NET_BIND_SERVICE`, `NOTIFY_SOCKET`
  inheritance, `resolvectl domain` restore) show that the unit-test fakes did not model these host behaviours;
  a VM matrix (Ubuntu/Fedora/Debian, with and without resolved) is the next verification step.
- Suggested upstream PR order: (1) `Axiom.Infrastructure.Unix` extraction + macOS facades, (2) `Axiom.Contracts`
  /`Axiom.Service` Linux hooks, (3) `Axiom.Infrastructure.Linux` without `Nft/`, (4) the `Nft/` engine + tests +
  e2e script, (5) docs.
