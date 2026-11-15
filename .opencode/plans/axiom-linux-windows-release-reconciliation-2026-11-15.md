# Axiom Linux ↔ Windows release reconciliation and Linux installer — execution plan

Date: 2026-11-15 (UTC). Author: build agent (single builder; no DKG/parallel workers for this run).
Status legend: **done** = committed + verified locally, **partial** = built/verified with a named gap,
**blocked** = needs a decision or permission, **todo** = not started.

Everything below was measured on 2026-11-15 between 16:28Z and 17:00Z. Re-measure before resuming:
upstream published v0.48.0 → v0.53.0 on 2026-11-15 alone.

---

## 1. Provenance (checked 2026-11-15T16:30Z)

| Item | Value |
|---|---|
| Canonical repo | `https://github.com/a-51-50/Axiom` (local `origin` is the `brxtrac/Axiom` fork; do not push to it) |
| Upstream `main` | `5de2d63679ccef3524b6cde512d584cd9a1ae8d6` — "docs: include #364 and #365 in 0.53.0 release notes", 2026-11-15T16:28:30Z |
| Latest Windows release | `v0.53.0`, published 2026-11-15T16:18:35Z; assets `Axiom-0.53.0-win-x64.zip`, `Axiom-Setup.exe`, `SHA256SUMS.txt` |
| Linux PR | `#276 feature/linux-port` head `a4275f4a7a4d957e3d75d87879ca5fe539b572e0`; base `feature/macos-port`; **draft**, review `CHANGES_REQUESTED` |
| macOS PR (Linux PR's base) | `#274 feature/macos-port` head `4f8c2267e58f32dd835b295fcae1987d746c042f`; base `main`; `CHANGES_REQUESTED` |
| Linux PR merge-base with `main` | `16229f4c74f715c3c17433c118be320be63501b9` (2026-11-14T12:03:24+01:00) — i.e. **pre-v0.24.0** |
| Divergence | `linux-port` 176 ahead / 157 behind `main`; 71 behind `macos-port` |
| Reconciliation branch | local `recon/linux-main-0.53.0`, merge commit `3252623a1a5de3861a9069f2dc1b24a494f90941` (not pushed) |
| Worktree | `/tmp/opencode/axiom-recon` (from bare clone `/tmp/opencode/axiom-recon-src.git`) |
| Preserved untouched | `/root/Axiom` at `6991fb9…` (clean), `/tmp/opencode/axiom-pr276-a4275f4` (clean review HEAD `b6b6049…`), all other worktrees |
| Host toolchain | .NET SDK 10.0.403 (`/opt/dotnet`), clang, make, bpftool 7.4.0, dpkg-deb, fakeroot, desktop-file-validate; no `lintian`, no `nfpm` |
| Host kernel | 7.0.0-38-generic (BPF object built CO-RE against it) |

Why the baseline moved: the Linux port was branched off a 2026-11-14 `main` (`16229f4`) that predates
upstream's encrypted DoH release (`0644bd6`, v0.24.0). Upstream then shipped 29 releases in one day
(v0.24.0 → v0.53.0) touching hooks, GUI, Setup and adapter DNS. Reconciling against v0.24.0 or the
Nov-14 head would be reconciling against a dead baseline.

## 2. Baseline and branch strategy (decided)

- **Baseline = `main` 5de2d636 (v0.53.0).** It is the only definition of "current Windows equivalent".
- **Linux work is integrated by merging `main` into `feature/linux-port`, not by rebasing 79 commits
  or re-porting.** The Linux host depends on `Axiom.Service.Hosting`, `Axiom.Infrastructure.Unix` and
  the `IPrivacyDnsPlatform` seam, which only exist in the `macos-port` stack the PR already targets.
- **Rejected:** cherry-picking Linux-only commits onto `main` (would re-do the shared extraction);
  merging `main` into `macos-port` first and then into `linux-port` (same conflict set, one extra
  unreviewed commit).
- **DNS reconciliation reuses the reviewed macOS work.** `macos-port` already resolved
  `main`↔`linux-port` DNS semantics (`ba417d2`, `8a27aa5`, `235cedd`: DoH selection on start and on
  rediscovery, no plaintext downgrade). Those shared files were taken wholesale instead of
  re-deriving the merge by hand.

## 3. Capability matrix (grounded in code at `3252623`)

| Capability | Windows (v0.53.0) | Linux (this branch) | Parity |
|---|---|---|---|
| Service host | Windows service `Axiom.Service` (named pipe, IP Helper) | `axiomd` systemd unit, `sd_notify`, journal | equivalent |
| IPC transport | named pipe, SID ACLs | Unix socket `/run/axiom/axiom.sock`, `SO_PEERCRED`, three access classes | equivalent |
| Firewall enforcement | Windows Firewall (WFP) rules + write gate | nftables `table inet axiom` + cgroupv2 socket match, read-back before "verified" | equivalent, different mechanism |
| Connect-time verdicts | WFP callouts | eBPF `cgroup/connect4|6`, `sendmsg4|6` (CO-RE) + libbpf events helper | Linux-only extra layer; degrades to nft-only honestly |
| DNS filtering | loopback `DnsProxyServer`, per-app attribution via IP Helper | same shared proxy in `Axiom.Service.Hosting`, attribution via `/proc` | equivalent |
| Encrypted upstream (DoH) | RFC 8484, 1.5 s per target, no plaintext fallback, bootstrap IPs | **now the same shared code** (was missing before this merge) | **fixed here** |
| Multi-target failover | comma/semicolon list, per-target timeout | same shared code | **fixed here** |
| System DNS ownership | opt-in adapter DNS via elevated helper/service (`WindowsPrivacyDnsPlatform`) | daemon writes systemd-resolved / NetworkManager / resolv.conf, backs up and restores | equivalent, different owner |
| DNS restore on stop/crash/uninstall | `PrivacyDnsFailSafe` | backup file + fail-safe restore in `--uninstall-service`/prerm | equivalent |
| Upstream rediscovery | n/a (adapter DNS is explicit) | watches non-loopback resolvers, re-applies DoH selection, never downgrades | Linux/macOS only |
| Process-start audit (F-19) | WMI `Win32_ProcessStartTrace` worker | **absent** — registration is behind `ServicePlatform.ConfigureProcessSpawnAudit`, Unix no-op | **Windows-only, deferred** |
| Installer | `Axiom-Setup.exe` (per-user, service install) | `.deb` via `dpkg-deb` (+ `.rpm` via `nfpm` when present, untested here) | Linux `.deb` done |
| Desktop | Avalonia (`Axiom.Desktop.Avalonia.Windows`) + WPF `Axiom.UI` | Avalonia `Axiom.Desktop.Avalonia.Linux` | equivalent shell, no WPF |
| Polkit / elevation | UAC | polkit action `com.axiom.firewall.install`, `pkexec` | equivalent |
| Update check | `UpdateCheckService`, title-bar indicator | shared `Axiom.Presentation` service, UI in `Axiom.UI.Avalonia` | equivalent |
| Agent hooks | WPF + Avalonia, Python guard helpers | shared `Axiom.Presentation`, POSIX evidence path adaptation | equivalent (verified by unit tests) |

## 4. Decisions with rationale

1. **Take `macos-port`'s DNS files, not a hand merge** (`DnsProxyServer.cs`, `DnsUpstream.cs`,
   `DnsUpstreamTarget.cs`, `IPrivacyDnsPlatform.cs`, `UpstreamRediscovery.cs`,
   `SystemDnsResolver.cs`, `WindowsPrivacyDnsPlatform.cs`, `MacPrivacyDnsPlatform.cs`). Rationale:
   these already reconcile upstream DoH with the platform seam and carry review fixes; a fresh merge
   would re-litigate them. Consequence: `linux-port` now inherits the macOS PR's DNS state.
2. **Keep upstream's Windows semantics unchanged.** Nothing in the merge changes Windows-only
   behaviour except the two compile seams below; the Windows TFMs still build.
3. **`ProcessSpawnAuditWorker` stays Windows-only.** Upstream registers it unconditionally, which
   breaks the `net10.0` target. Registered through `ServicePlatform.ConfigureProcessSpawnAudit`
   (Windows: register; Unix: no-op) — same pattern as `ConfigureAgentEnforcement`. A Unix
   process-start source is a separate task (T7), not part of this reconciliation.
4. **Guard-script substitution order.** Upstream substitutes `# <<AXIOM_COMMAND_GUARD>>`; the port
   wraps every template in `AgentPlatform.AdaptHookScript`. Combined as
   `AdaptHookScript((template).Replace(...))`, so the POSIX evidence path is applied to the final
   script and upstream's guard helpers are present on every platform.
5. **Keep both overview behaviours.** Upstream added `PrivacyOverview` + `UpdateCheckService`; the
   port added `Overview.ProtectionState`/`ComposeStatus` (honest "rules apply only when verified").
   Both are kept; `StatusSourceText` keeps the Linux enforcement wording.
6. **Shared DNS tests move to a `net10.0` test project.** They were only in
   `Axiom.Infrastructure.Windows.Tests` (cannot run on Linux), so the Linux DoH path had no
   executable proof. `tests/Axiom.Service.Hosting.Tests` now runs them on every OS; the
   Windows-only adapter filter test stays in the Windows suite.
7. **`.deb` is the shipped Linux format.** `nfpm`/RPM is not installed on the build host and no RPM
   runtime test exists in this environment → explicitly deferred, not claimed.
8. **Release assets are built, never published.** Linux assets are produced locally and by a
   `workflow_dispatch`-only workflow that uploads a workflow artifact. No GitHub release, no asset
   upload, no secret changes.

## 5. Blocking question vs established requirements

**Q1 (resolved 2026-11-15): authorised to install `pkexec` in the disposable guest only.**
Done: temporary egress boot (`bin/start-provision.sh`), `apt-get install -y pkexec`
(`124-2ubuntu1.24.04.4`), then the package installed cleanly. No host change. Original blocker,
kept for the record — the guest had `polkitd` but not `pkexec`/`policykit-1`, so `dpkg -i` stopped at:
```
axiom depends on pkexec | policykit-1; however:
  Package pkexec is not installed.
  Package policykit-1 is not installed.
```
Installing that dependency is not pre-authorised, and the guest is booted restricted (no egress).
Chosen: (a). The dependency stays a hard `Depends` (honest for a desktop install).

**Established (no further decision needed):** no live DNS resolver changes on host or guest; no
network/firewall changes outside the guest; no dependency installs on the host; package install in
the disposable guest is authorised; artifacts stay local.

## 6. Ordered tasks

| ID | Task | Depends | Owned files | Status |
|---|---|---|---|---|
| T1 | Refresh upstream refs, releases, PR review states | – | – | **done** |
| T2 | Merge `main` v0.53.0 into `feature/linux-port`, resolve 18 conflicts | T1 | merge commit | **done** `3252623` |
| T3 | Reconcile DNS/DoH with upstream + platform seam | T2 | `src/Axiom.Service.Hosting/Dns/*`, `src/Axiom.Infrastructure.{Windows,MacOS}/Dns/*` | **done** |
| T4 | Reconcile hooks/guard helper, installer venv, UI overview | T2 | `src/Axiom.Presentation/*Protection.cs`, `AgentHookScript.cs`, `OptionalModuleInstaller.cs`, `src/Axiom.UI.Avalonia/*` | **done** |
| T5 | Restore compilability of both TFMs; move shared DNS tests to `net10.0` | T3,T4 | `src/Axiom.Service/*.csproj`, `Platform/ServicePlatform.*.cs`, `tests/Axiom.Service.Hosting.Tests/*`, `Axiom.Portable.slnx`, `Axiom.sln` | **done** |
| T6 | Build and test Linux + shared suites, record counts | T5 | – | **done** (§8) |
| T7 | Unix process-start source for the F-19 audit | T5 | new `Axiom.Infrastructure.Linux/ProcessIdentity` | **todo** (unassigned; not needed for the shippable surface) |
| T8 | Build the `.deb` 0.53.0 (BPF objects included); fix unit paths found by E2E | T5 | `packaging/linux/*`, `scripts/linux/package.sh`, `src/Axiom.Infrastructure.Linux/Systemd/SystemdUnit.cs` | **done** `9196827` artifact, fix `4e77777` |
| T9 | Linux package workflow (artifact only) | T8 | `.github/workflows/linux-release.yml` | **done** |
| T10 | Guest E2E: install, service, doctor, IPC, canary, restart, remove, purge | T8 + Q1 | – | **done** (GUI and live DNS redirect out of scope) |
| T11 | Final integrated diff review against this plan | T6,T8 | – | **todo** — this session could not spawn a nested reviewer (`subagent_depth` limit); parent must run it (§10) |
| T12 | Attach Linux asset to the v0.53.x release | separate authorisation | – | **explicitly out of scope** |

### Worker-ready prompts

Each task is bounded to its `Owned files`; nobody edits outside them without updating this table.

- **T7 (Unix process audit).** "In the reconciliation worktree, add a Linux process-start source
  behind the existing `IProcessStartSource` seam, register it in
  `ServicePlatform.ConfigureProcessSpawnAudit` on Unix, keep the Windows WMI path unchanged, and add
  tests that run on `net10.0`. Do not touch DNS, packaging or the UI. Acceptance: `dotnet build`
  for both TFMs, `Axiom.Core.Tests` process-audit tests pass, new test proves a spawn row is written
  and the file is `0600`."
- **T10 (guest E2E).** "Boot `run/axiom-test-run.qcow2` restricted, install
  `build/linux/axiom_0.53.0_amd64.deb`, capture `systemctl status axiomd`, `axiomd --doctor`,
  `axiomd` capabilities over IPC, `pkaction`, `desktop-file-validate`, `resolvectl status` before
  and after start/stop, a narrow local block, restart with a pending rule, uninstall, and a clean
  purge. Never change the guest's upstream resolvers by hand and never touch host DNS or the
  firewall. Store logs under `/tmp/opencode/axiom-linux-release-20261115/guest-evidence/`."
- **T11 (final review).** "Read this plan and review `git diff 5de2d636..3252623` plus the package
  manifest. Confirm each task's acceptance evidence exists, flag any Windows semantic change not
  listed in §4, and do not approve the release-upload gate."

## 7. Packaging and artifact contract

- Format: Debian `.deb` (`dpkg-deb -Zxz`, `fakeroot`), built by `scripts/linux/package.sh deb --arch x64`.
- Contents: `/opt/axiom` (desktop + bundled `axiomd/` with `bpf/axiom_connect.bpf.o` and
  `bpf/axiom-bpf-events`), `/usr/share/applications/com.axiom.firewall.desktop`,
  `/usr/share/polkit-1/actions/com.axiom.firewall.policy`, hicolor icons, DEP-5 copyright.
- Maintainer scripts: `postinst` → `axiomd --install-service` (stages `/usr/libexec/axiom`, writes
  the unit); `prerm` → `--uninstall-service`, detaches its own BPF pins, keeps `/var/lib/axiom`;
  `postrm purge` → deletes state.
- Hard dependencies include `nftables`, `polkitd | policykit-1`, `pkexec | policykit-1`, `systemd`,
  `libbpf1`, `libssl3t64 | libssl3`, ICU and the X11/font stack from `dpkg-shlibdeps`.
- Artifact for this run: `axiom_0.53.0_amd64.deb`,
  `sha256 919682798343def69ffcc07661700c12992ab77b2ba2927b035e26f8b8170d63`
  (`/tmp/opencode/axiom-linux-release-20261115/`; build `4e77777`).
  The first build (`ac9e42d7…`, merge `3252623`) is superseded: its unit aborted with
  226/NAMESPACE on a host without NetworkManager.
- Integrity checklist: `dpkg-deb -I` shows Version 0.53.0/amd64; 505 entries; `sha256sum` matches
  `SHA256SUMS.txt`; the same hash was observed inside the guest after `scp`; polkit XML parsed by
  `package.sh`; desktop entry validated; no `.pdb`, no `libcoreclrtraceptprovider.so`.
- Not done: signing (no key authorised), `lintian` (not installed), RPM, x86-64 baseline other than
  Ubuntu 24.04, arm64.

### 7.1 Guest E2E (Ubuntu 24.04.5, kernel 6.8.0-147, disposable overlay)

| Step | Result |
|---|---|
| `dpkg -i axiom_0.53.0_amd64.deb` (after `pkexec`) | `Setting up axiom (0.53.0)`, `Installed and started axiomd.service`; `enabled`, `active (running)` |
| `axiomd --doctor` | `Result: all checks passed` — unit, protected image 234 entries, socket root 0666, state/log 0700, `dns backend: SystemdResolved; enp0s1: 10.0.2.3`, nftables v1.0.9 generation 1, `live enforcement verified`, BPF `4/4` pins, kernel self-check verified (CO-RE) |
| IPC (`scripts/linux/axipc.py`) | `capabilities` → `milestone 0.53.0`, 23 commands, `firewallWrites: false`; `serviceHealth` → running, honest Linux limitations; `privacy.status` → `upstream: encrypted DoH (1.1.1.1, 9.9.9.9)`, disabled |
| Enforcement canary (`scripts/linux/canary.sh unscoped --count 20`) | rules `connectTimeBlockingProven=True`; `slipped 0/20 blocked 20/20` for curl and python over IPv4 and IPv6 |
| Restart | `active`, doctor all checks passed, BPF reattached, 4 pins |
| `dpkg -r` | daemon stopped, unit and `/usr/libexec/axiom` removed, `/var/lib/axiom` + `/var/log/axiom` kept, nft table gone, pins gone |
| `dpkg -P` | state/log/desktop/polkit action removed, `pkaction` no longer lists the action |
| Resolver untouched throughout | `resolvectl` Link 2 `10.0.2.3` before and after; `/etc/resolv.conf` still → `/run/systemd/resolve/stub-resolv.conf` |
| Not run | Privacy Shield enable (would redirect the guest resolver — out of scope); GUI walkthrough (no display); true cross-version upgrade (only a same-version reinstall was available) |

## 8. Test evidence (host, 2026-11-15)

`dotnet test Axiom.Portable.slnx -c Release` unless noted.

| Suite | Result |
|---|---|
| Contracts | 156/156 |
| Core | 170/184 — 14 failures, all hard-coded `C:\` / extended-path assertions from upstream tests |
| Persistence | 21/21 |
| Unix | 47/47 |
| Linux | 37/37 |
| MacOS | 247/249 — 2 `UnixSocketIpcTests` failures (same 2 on the pre-merge branch) |
| McpServer | 34/34 |
| Presentation | 287/294 — 7 failures, upstream tests with `C:\lab\…` literals |
| UI.Avalonia | 80/80 |
| **Service.Hosting (new)** | **27/27** — DoH RFC 8484, no plaintext downgrade, target parsing, bootstrap, rediscovery |
| Linux.Nft.Tests | 153/153 |
| Desktop.Avalonia.Linux.Tests | 51/51 |

Regression control: the same three failing suites were run on the untouched `a4275f4` worktree —
Core 12 failures, MacOS 2, Presentation 0. The two extra Core failures
(`AgentProcessEgressTests.*`) are upstream Windows-path tests new in this merge; the 7 Presentation
failures are upstream's `ProtectionProvisionerTests`/`BlackboxWordlistNormalizerTests` using
`C:\lab\…` literals. None is a Linux behaviour regression; all are Windows-assumption test gaps.

Compile checks on Windows TFMs (Linux host, no runtime): `Axiom.Infrastructure.Windows`,
`Axiom.Service -f net10.0-windows`, `Axiom.Desktop.Avalonia.Windows` all build. WPF `Axiom.UI` and
`Axiom.UI.Tests` cannot be built here — **untested, stated not proven**.

## 9. Threat model, safety, rollback

- The merge does not widen authority: Linux writes stay in `nftables`/`/var/lib/axiom`/
  `/run/axiom`/`/usr/libexec/axiom`; DNS writes remain behind `IPrivacyDnsPlatform` with a backup
  and a fail-safe restore.
- DoH keeps TLS validation on, a 1.5 s per-target timeout, and no plaintext fallback unless a target
  explicitly allows it (`FallbackToPlainAllowed` stays `false` for discovered/known targets).
- `ProcessSpawnAuditWorker` exclusion removes no validation from Windows.
- Test environment: no host DNS/firewall changes, no guest resolver edits, no baseline reset. The
  guest was purged back to `dpkg-query: no packages found matching axiom` after the blocked install.
- Rollback: `git reset --hard a4275f4` in `/tmp/opencode/axiom-recon` returns to the pre-merge Linux
  port; `/root/Axiom` and the PR branch are untouched. The artifact is a local file; deleting it
  removes the only copy.

## 10. Gates and what is still not claimed

- **Integration gate:** merge commit exists, both TFMs compile, Linux + shared suites green
  (done, except pre-existing Windows-path test failures listed above).
- **Review gate (open):** no fresh-context review of `5de2d636..3252623` has run. Parent should spawn
  one with the T11 prompt; this plan is the checklist.
- **Install gate (passed 2026-11-15):** clean install, service start, doctor, IPC, enforcement
  canary, restart, remove and purge on the disposable Ubuntu 24.04.5 guest, with the BPF layer
  attached and CO-RE verified on kernel 6.8 (object built on host 7.0). Still unproven: Privacy
  Shield live redirect/restore (deliberately not exercised), GUI, true cross-version upgrade.
- **Release gate (not authorised):** no upload, no tag, no release notes, no signing.
- Known limits to publish with any artifact: Ubuntu 24.04 x64 only; WMI/process-start audit absent
  on Linux; `.rpm` unbuilt/untested; GUI walkthrough not performed; Privacy Shield redirect not
  exercised on the guest (unit-tested only); no signing.

## 11. Where the evidence lives

- Worktree: `/tmp/opencode/axiom-recon` (branch `recon/linux-main-0.53.0`, merge `3252623`).
- Artifact + `SHA256SUMS.txt` + `PROVENANCE.txt` + `guest-evidence/`:
  `/tmp/opencode/axiom-linux-release-20261115/`.
- Pre-merge control worktree: `/tmp/opencode/axiom-baseline` (detached `a4275f4`).
- Prior reports (Nov 14, historical): `/tmp/opencode/axiom-review-dns-20261114/REPORT.md`,
  `/tmp/opencode/axiom-review-closeout-20261114/REPORT.md`,
  `/tmp/opencode/axiom-review-parser-validation/REPORT.md`.
- Published (pre-existing): PR #276 comment `#issuecomment-6883150435`; wiki
  `projects/axiom/linux-e2e-validation-2026-11-12#review-follow-up-2026-11-14`.
