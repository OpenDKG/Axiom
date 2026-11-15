# Axiom Linux ↔ Windows release reconciliation and Linux installer — execution plan

Date: 2026-11-15 (UTC). Author: build agent (single builder; no DKG/parallel workers for this run).
Status legend: **done** = committed + verified locally, **partial** = built/verified with a named gap,
**blocked** = needs a decision or permission, **todo** = not started.

Everything below was measured on 2026-11-15 between 16:28Z and 17:00Z. Re-measure before resuming:
upstream published v0.48.0 → v0.53.0 on 2026-11-15 alone.

Revision 2 (2026-11-15T22:2xZ, single builder): an independent review rejected HEAD `7fad752`.
The eight bounded findings (§12) are fixed in `821237d`; the counts and provenance below are the
post-fix measurements. Review status: **not approved — fresh independent review required**.

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

## 5. Authorisation provenance and the guest

**No explicit approval record establishes permission for the earlier guest provisioning.**
What is known to have happened on 2026-11-15 (recorded as actions, not as permission):
- the disposable guest was booted with a temporary egress profile (`bin/start-provision.sh`),
- `apt-get install -y pkexec` (`124-2ubuntu1.24.04.4`) was run inside that guest,
- the original `.deb` was installed and exercised, then purged.

A successful command is not evidence of authorisation. No repository record (plan, comment,
issue or operator note) explicitly approves guest egress or dependency installation; treat the
provisioning as **authorisation not established** and do not repeat it. This session did not
provision, install dependencies, change host/guest DNS, firewall or network, or use egress. It
reused the existing disposable overlay (which already had `pkexec`) for local install, health,
enforcement, restart, remove and purge only.

Established constraints (unchanged): no live DNS resolver changes on host or guest; no network
or firewall changes outside the guest; no dependency installs on the host; local artifacts only.

The original blocker, kept for the record — the guest had `polkitd` but not
`pkexec`/`policykit-1`, so `dpkg -i` stopped at:
```
axiom depends on pkexec | policykit-1; however:
  Package pkexec is not installed.
  Package policykit-1 is not installed.
```
The dependency stays a hard `Depends` (honest for a desktop install). Installing it is not
pre-authorised.

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
| T8 | Build the `.deb` 0.53.0 (BPF objects included); fix unit paths found by E2E; rebuild after review fixes | T5 | `packaging/linux/*`, `scripts/linux/package.sh`, `src/Axiom.Infrastructure.Linux/Systemd/SystemdUnit.cs` | **done** — artifact `ce966fa9…` from `821237d`; verified pins script |
| T9 | Linux package workflow (artifact only, provenance handoff) | T8 | `.github/workflows/linux-release.yml` | **done** — downloadable artifact + `PROVENANCE.txt`; no release attachment |
| T10 | Guest E2E: install, service, doctor, IPC, canary, restart, remove, purge | T8 | – | **done** (second run, §7.1; GUI and live DNS redirect out of scope) |
| T11 | Independent final review of the integrated diff against this plan | T6,T8 | – | **todo / rejected at `7fad752`** — fixes applied in `821237d`; a fresh review is required and this plan does not approve the result |
| T12 | Linux release automation: local build + handoff to the approved release pipeline | T8 | `.github/workflows/linux-release.yml`, `scripts/linux/package.sh` | **partial** — the local `.deb` and a workflow artifact (with checksums/provenance) are ready for an approved release workflow. Attaching the asset to a public GitHub release is **not implemented** and needs a separate gated task with release-write permission. |

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
- **T11 (final review).** "Read this plan and review `git diff 5de2d636..<final commit>` plus the
  package manifest. Confirm each task's acceptance evidence exists, flag any Windows semantic
  change not listed in §4, and do not approve the release-upload gate." A fresh reviewer must also
  re-check §12 findings 1–8 against `821237d`.
- **T12 (release automation, not publication).** "Build `build/linux/axiom_0.53.0_amd64.deb` with
  `scripts/linux/package.sh deb --arch x64` or run the `workflow_dispatch`-only `linux-release.yml`
  job, record the SHA-256, `PROVENANCE.txt` and `SHA256SUMS.txt`, and hand them to the approved
  release workflow. Do **not** create a tag, a GitHub release, upload an asset, push, sign or change
  secrets. Automatic attachment to a public release is a separate future task that requires
  explicit release-write authorisation; do not claim it as implemented."

## 7. Packaging and artifact contract

- Format: Debian `.deb` (`dpkg-deb -Zxz`, `fakeroot`), built by `scripts/linux/package.sh deb --arch x64`.
- Contents: `/opt/axiom` (desktop + bundled `axiomd/` with `bpf/axiom_connect.bpf.o` and
  `bpf/axiom-bpf-events`), `/usr/share/applications/com.axiom.firewall.desktop`,
  `/usr/share/polkit-1/actions/com.axiom.firewall.policy`, hicolor icons, DEP-5 copyright.
- Maintainer scripts: `postinst` → `axiomd --install-service` (stages `/usr/libexec/axiom`, writes
  the unit; an unconfirmed stop refuses the replacement); `prerm` → `--uninstall-service`,
  detaches its own BPF pins only after `bpftool` proves no attachment, keeps `/var/lib/axiom` on
  an unknown/failed state; `postrm purge` → deletes state.
- Hard dependencies include `nftables`, `polkitd | policykit-1`, `pkexec | policykit-1`, `systemd`,
  `libbpf1`, `libssl3t64 | libssl3`, ICU and the X11/font stack from `dpkg-shlibdeps`.
- **Current artifact (revision 2):** `axiom_0.53.0_amd64.deb`, 63,040,292 bytes,
  `sha256 ce966fa9de012e31730994e2aebb6a2f140632b1311f920398d26b5ec009f356`, built from `821237d`
  (`.deb` at `/tmp/opencode/axiom-recon/build/linux/`; copy in
  `/tmp/opencode/axiom-recon-review-fixes/`). It contains 506 entries (the 505 of the previous
  build plus `/opt/axiom/bpf-pins.sh`).
- **Superseded, not deliverable:** `919682798343def69ffcc07661700c12992ab77b2ba2927b035e26f8b8170d63`
  (`/tmp/opencode/axiom-linux-release-20261115/`, 63,032,704 bytes, 505 entries, build `4e77777`)
  is the artifact the review rejected (missing reviewed BPF fixes, unsafe prerm/stop handling,
  `-/etc/resolv.conf` regression). Keep it only as evidence; do not ship or install it. The
  earlier `ac9e42d7…` build (merge `3252623`) is also superseded (226/NAMESPACE unit abort).
- Integrity checklist: `dpkg-deb -I` shows Version 0.53.0/amd64; 506 entries; `sha256sum` matches
  `SHA256SUMS.txt`; the same hash was observed inside the guest after `scp`; polkit XML parsed by
  `package.sh`; desktop entry validated; no `.pdb`, no `libcoreclrtraceptprovider.so`.
- Not done: signing (no key authorised), `lintian` (not installed), RPM (no runtime test), x86-64
  baseline other than Ubuntu 24.04, arm64.

### 7.1 Guest E2E (second run, 2026-11-15T22:21Z, Ubuntu 24.04.5, kernel 6.8.0-147, existing disposable overlay)

The overlay was booted **restricted** (`no default route`, loopback SSH only). No provisioning,
dependency install, DNS/firewall change or egress was performed; `pkexec` was already present.

| Step | Result |
|---|---|
| Pre-state | `dpkg-query` no axiom; `pkexec 124`; `axiomd` inactive; `/etc/resolv.conf` → stub |
| `sha256sum` after `scp` | `ce966fa9…` matches the host artifact |
| `sudo dpkg -i axiom_0.53.0_amd64.deb` | `Setting up axiom (0.53.0)`, `Installed and started axiomd.service`; `active`, `enabled` |
| `axiomd --doctor` | `Result: all checks passed` — image 234 entries, socket 0666, state/log 0700, nftables generation 1, `live enforcement verified`, BPF `4/4` pins, CO-RE self-check verified |
| IPC (`axipc.py`) | `capabilities` milestone 0.53.0, `firewallWrites: false`; `serviceHealth`/`privacy.status` answered (privacy disabled, no redirect) |
| Canary (`canary.sh unscoped --count 10`) | `connectTimeBlockingProven=True`; `slipped 0/10 blocked 10/10` for curl and python, IPv4 and IPv6 |
| Packaged pin cleanup (`/opt/axiom/bpf-pins.sh`) | fake `bpftool` unreadable → refused, pins kept; `[]` → pins removed (both in a temp pin dir) |
| Restart | `active`, doctor all checks passed, BPF reattached 4/4 pins |
| `dpkg -r` | daemon stopped, unit/`/usr/libexec/axiom`/pins removed, nft table gone, `/var/lib/axiom` + `/var/log/axiom` kept |
| `dpkg -P` | state/log/desktop/polkit action removed; `dpkg-query` no package |
| Resolver untouched throughout | `/etc/resolv.conf` still → `/run/systemd/resolve/stub-resolv.conf`; no link resolver written |
| Not run | Privacy Shield enable (would redirect the guest resolver — out of scope); GUI walkthrough (no display); upgrade over the rejected old artifact (unsafe; not installed). Installer stop-failure/timeout paths are covered by injected-runner unit tests, not by breaking systemd in the guest |


## 8. Test evidence (host, revision 2, 2026-11-15T17:1xZ)

`dotnet test` per project in Release. This run was as **root** on Linux (host kernel 7.0.0-38).

| Suite | Result |
|---|---|
| Contracts | 156/156 |
| Core | **184/184** — the Windows-path fixtures now run on Linux (`RuleSpecValidator`, agent path rules, normalisation) |
| Persistence | 21/21 |
| Unix | 47/47 |
| Linux | **52/52** — 37 previous + 7 installer stop/unknown/absent/idempotence + 8 shell pin-cleanup cases |
| MacOS | **249/249** — the root-run socket pair now injects peer uid 501, so the non-root cap and read-only policy are exercised |
| McpServer | 34/34 |
| Presentation | **294/294** — config paths built with `Path.Combine`, separator-agnostic wordlist assertions |
| UI.Avalonia | 80/80 |
| **Service.Hosting** | **31/31** — DoH/Rediscovery 27 + 4 release-script framework checks |
| Linux.Nft.Tests | **160/160** — the 7 reviewed BPF tests restored |
| Desktop.Avalonia.Linux.Tests | 51/51 |

`Axiom.Portable.slnx` itself does not include `Linux.Nft.Tests`; it was run separately. The earlier
"14 Core / 7 Presentation / 2 MacOS pre-existing failures" claim is withdrawn: the failures were a
mix of a Linux-only product bug (Windows absolute paths rejected) and platform-specific fixtures,
and they are fixed rather than excused.

Windows cross-compile (Linux host, no Windows runtime): `Axiom.Infrastructure.Windows`,
`Axiom.Service -f net10.0-windows`, `Axiom.Desktop.Avalonia.Windows`, and
`tests/Axiom.Service.Tests` (compiles the factory-wiring test) all build. A `dotnet publish` of the
service with `-f net10.0-windows -r win-x64 --self-contained -p:PublishSingleFile=true` produced a
40,538,256-byte `Axiom.Service.exe`; without `-f` it fails `NETSDK1129` (the regression the scripts
now guard). WPF `Axiom.UI`/`Axiom.UI.Tests` and the full `Axiom.sln` locked restore cannot run here
(`NETSDK1100`, Windows-only WPF) — **untested, stated not proven**. No Windows runtime execution is
claimed.

Locked restore: `dotnet restore Axiom.Portable.slnx --locked-mode` passes; `tests/Axiom.Service.Tests/packages.lock.json`
was stale (0.34.0 project refs) and is corrected to 0.53.0 so its locked restore passes. RID publish
lock changes were discarded (`git checkout -- '*.lock.json'`); no unrelated lock churn remains.

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

- **Integration gate:** merge commit exists, both TFMs compile, all portable/Linux suites green
  (revision 2 counts in §8).
- **Review gate (open, rejected once):** the review of `5de2d636..7fad752` rejected eight findings;
  they are fixed in `821237d` and need a **fresh independent review** of `5de2d636..<final commit>`.
  This plan does not approve itself, and no GitHub/wiki readiness is claimed.
- **Install gate (passed twice):** clean install, service start, doctor, IPC, enforcement canary,
  restart, remove and purge on the disposable Ubuntu 24.04.5 guest, BPF attached and CO-RE verified
  on guest kernel 6.8 (object built on host 7.0). Still unproven: Privacy Shield live
  redirect/restore (deliberately not exercised), GUI, cross-version upgrade, guest failure injection
  for the installer stop path (covered by injected-runner unit tests only).
- **Release gate (not authorised):** no upload, tag, release notes, signing, push or deployment.
  T12 only prepares local/workflow artifacts for an approved release workflow.
- Known limits to publish with any artifact: Ubuntu 24.04 x64 only; WMI/process-start audit absent
  on Linux; `.rpm` unbuilt/untested; GUI walkthrough not performed; Privacy Shield redirect not
  exercised on the guest (unit-tested only); no signing; Windows runtime not executed on this host.
- DoH status is not proof of an encrypted query: the unit tests use fake handlers and a local TLS
  mock can prove the protocol only; no live public DNS query is claimed.

## 11. Where the evidence lives

- Worktree: `/tmp/opencode/axiom-recon` (branch `recon/linux-main-0.53.0`, fixes `821237d`).
- Revision-2 artifact + `SHA256SUMS.txt` + guest logs:
  `/tmp/opencode/axiom-recon-review-fixes/` (`.deb` `ce966fa9…`, 63,040,292 bytes).
- Rejected revision-1 artifact (evidence only, do not ship):
  `/tmp/opencode/axiom-linux-release-20261115/`.
- Pre-merge control worktree: `/tmp/opencode/axiom-baseline` (detached `a4275f4`).
- Prior reports (Nov 14, historical): `/tmp/opencode/axiom-review-dns-20261114/REPORT.md`,
  `/tmp/opencode/axiom-review-closeout-20261114/REPORT.md`,
  `/tmp/opencode/axiom-review-parser-validation/REPORT.md`.
- Published (pre-existing): PR #276 comment `#issuecomment-6883150435`; wiki
  `projects/axiom/linux-e2e-validation-2026-11-12#review-follow-up-2026-11-14`.

## 12. Review findings fixed in `821237d`

| # | Finding | Fix (files) | Evidence |
|---|---|---|---|
| 1 | Approved BPF fixes lost; `BpfEngine.cs` byte-identical to `a4275f4` | Took the reviewed files from `b6b6049` (`3feb3c9`, `a9a673b`, `b68263f`, `b6b6049`): failed detach is not success, unreadable/malformed inspection keeps state unknown, invalid ids/undecodable names rejected, shutdown success only after a readable zero, pins kept and no second load | `BpfEngine.cs`; 7 new tests; Nft 160/160 |
| 2 | Windows factory passed only `RestoreIfNeeded`, so adapter-DNS persistence was disabled | `ServicePlatform.Windows.CreateDefaultPrivacyDnsPlatform` passes all three delegates (macOS `4f8c2267` wiring) + wiring test | `ServicePlatform.Windows.cs`, `PrivacyDnsPlatformWiringTests.cs` (compiles under `net10.0-windows`) |
| 3 | Windows service publish/run lacked `-f net10.0-windows` (fails NETSDK1129) | Added the framework to `publish-setup.ps1`, `build-release.ps1`, `build-msix.ps1`, `run-service.ps1`; portable regression test reads the scripts | `ReleaseScriptTests.cs`; cross-compiled `Axiom.Service.exe`; unqualified publish fails as expected |
| 4 | `/etc/resolv.conf` lost its `-` optional prefix | Restored `-/etc/resolv.conf` (required state/run/cgroup/bpf stay bare) and the reviewed `UnitTreatsMissingOptionalResolverPathsAsNonFatal` test | `SystemdUnit.cs`, `SystemdAndPathsTests.cs` |
| 5 | `prerm` ignored detach failure/unavailable bpftool and unpinned | Shared `packaging/linux/bpf-pins.sh`: detach, read back `bpftool -j cgroup show`, only a readable array with no `axiom_*` entry allows `rm`; otherwise fail and keep pins. Used by Debian prerm and RPM %preun; packaged at `/opt/axiom/bpf-pins.sh` | 8 shell tests (fake bpftool: normal, stale, unreadable, malformed, attached, failed detach, missing, absent dir) + guest smoke |
| 6 | Installer replaced the image after an unconfirmed stop; uninstall removed unit/image and claimed "not running" | `WaitForStop` accepts only `inactive`/`failed`; install/uninstall return 8 and keep image/unit/recovery state on unknown or still-active; absent service still installs/uninstalls (idempotent) | 7 injected-runner tests (failure, timeout, absent, normal, uninstall failure/unreadable/idempotent) |
| 7 | Portable suites not green | Product: Windows-absolute paths accepted on Linux in `RuleSpecValidator`/`AgentNetworkControl`; separator-aware `AgentExecutables`; UNC checked before absolute. Fixtures: config paths via `Path.Combine`, separator-agnostic assertions, root-run IPC peer uid seam | §8: Core 184, Presentation 294, MacOS 249, Linux 52, Nft 160, Hosting 31 |
| 8 | Plan claimed guest egress/pkexec permission and an older artifact as deliverable | §5 now records actions without invented approval ("authorisation not established"); §7 marks the old `.deb` superseded/non-deliverable and records the new SHA; T12 clarified as local/workflow handoff only | this plan; workflow provenance step |
