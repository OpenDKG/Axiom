# Axiom Linux ↔ Windows release reconciliation and Linux installer — execution plan

Date: 2026-11-15 (UTC). Author: build agent (single builder; no DKG/parallel workers for this run).
Status legend: **done** = committed + verified locally, **partial** = built/verified with a named gap,
**blocked** = needs a decision or permission, **todo** = not started.

Everything below was measured on 2026-11-15 between 16:28Z and 23:06Z. Re-measure before resuming:
upstream published v0.48.0 → v0.53.0 on 2026-11-15 alone.

Revision 2 (2026-11-15T22:2xZ, single builder): an independent review rejected HEAD `7fad752`.
The eight bounded findings (§12) are fixed in `821237d`; the counts and provenance below are the
post-fix measurements. It was superseded by revision 3; its artifact is evidence only.

Revision 3 (2026-11-15T22:5xZ, single builder): a fresh review of `400d4a9` (packaged inputs
`821237d`) rejected exactly two HIGH blockers: the pin script's fake JSON acceptance (§12.9) and
`postrm` deleting the unit/image after an ignored stop failure (§12.10). Both are fixed in
`dc2d9cd`; revision-3 artifact `35433682…` was rebuilt from that commit. A further independent
review **approved** local commit `47c39da` and that exact artifact (local review only, not a
release). A bounded live pass on 2026-11-15T23:02Z–23:06Z then installed the approved `.deb`
through the normal `dpkg -i` path on the existing Ubuntu 24.04.5 overlay (no force, no
provisioning) and passed service, doctor, BPF, IPC, canary, restart durability, remove and purge
(§7.2). Review status: **approved locally; not release-published and not upstream-merged**.

Revision 4 (2026-11-16T02:0xZ UTC, single builder): the upstream baseline moved after revision 3
(`main` v0.53.0 → v0.59.0, PR #276 head → `1827deb`, owner decision to rename the package
`axiom-firewall`). Revision 4 merges v0.59.0 into local branch `recon/linux-main-0.59.0`
(HEAD `126de46`), ports the package rename and the legacy-package purge disarm, rebuilds
`axiom-firewall_0.59.0_amd64.deb` (`a09a88d9…`) and re-runs the guest matrix, including the first
genuine cross-version upgrade and a local TLS DoH proof. **Independent review of `126de46` has not
been done yet** (subagent depth limit); the prior approval covers `47c39da` only. See §13.

---

## 1. Provenance (checked 2026-11-15T16:30Z)

| Item | Value |
|---|---|
| Canonical repo | `https://github.com/a-51-50/Axiom` (local `origin` is the `brxtrac/Axiom` fork; do not push to it) |
| Reconciliation target (revision 3) | `5de2d63679ccef3524b6cde512d584cd9a1ae8d6` — v0.53.0, 2026-11-15T16:28:30Z |
| Current upstream `main` (revision 4) | `28918945b729dd4903c80c144cc8cf2416dee40e` — "feat(ui,brand): … release 0.59.0", 2026-11-16T01:19:52Z |
| Latest Windows release | `v0.59.0`, published 2026-11-16T01:20:38Z; assets `Axiom-0.59.0-win-x64.zip`, `Axiom-Setup.exe`, `SHA256SUMS.txt` |
| Delta after the 0.53 target | v0.54.0 shared fixes; v0.55/0.56 brand assets; v0.57 themes; v0.58 docs screenshots; v0.59 UI/nav/brand. See §13 |
| Linux PR | `#276 feature/linux-port` head `1827deb11de7674dab96555a3a1071dcafc39921`; base `feature/macos-port`; **draft**, `CHANGES_REQUESTED`; owner comment 2026-11-15T20:14Z decides `axiom-firewall` for DEB/RPM |
| macOS PR (Linux PR's base) | `#274 feature/macos-port` head `4f8c2267e58f32dd835b295fcae1987d746c042f`; base `main`; `CHANGES_REQUESTED` |
| Linux PR merge-base with `main` | `16229f4c74f715c3c17433c118be320be63501b9` (2026-11-14T12:03:24+01:00) — i.e. **pre-v0.24.0** |
| Reconciliation branches | `recon/linux-main-0.53.0` HEAD `3d7ccf1` (approved local, prior); `recon/linux-main-0.59.0` HEAD `126de46` (revision 4, not independently reviewed) |
| Worktree | `/tmp/opencode/axiom-recon` (from bare clone `/tmp/opencode/axiom-recon-src.git`) |
| Preserved untouched | `/root/Axiom` at `6991fb9…` (clean), `/tmp/opencode/axiom-pr276-a4275f4` (clean review HEAD `b6b6049…`), all other worktrees |
| Host toolchain | .NET SDK 10.0.403 (`/opt/dotnet`), clang, make, bpftool 7.4.0, dpkg-deb, fakeroot, desktop-file-validate, rpmbuild; no `lintian`, no `nfpm`, no Xvfb |
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
| Installer | `Axiom-Setup.exe` (per-user, service install) | `.deb` via `dpkg-deb` (+ `.rpm` via `nfpm` when present, untested here) | Linux `.deb` done; package is `axiom-firewall` since revision 4 |
| Package identity | Windows installer / `Axiom-Setup.exe` | `axiom-firewall` DEB/RPM, `Conflicts`/`Replaces: axiom (<< 1000)` so the archive `axiom` package is untouched | owner-decided in #276; migration tested |
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

That provisioning sits between the 16:49Z blocked install (which recorded `pkexec` absent, §7.3)
and the 17:21Z revision-2 run (which found it installed). A successful command is not evidence of
authorisation. No repository record (plan, comment, issue or operator note) explicitly approves
guest egress or dependency installation; treat the provisioning as **authorisation not
established** and do not repeat it.

The final live pass (23:02Z, §7.2) did not provision, install a dependency, change host/guest
DNS, firewall or network, or use egress. It checked the dependency by dpkg status only:
`pkexec 124-2ubuntu1.24.04.4` and `polkitd` were already `ii` in the overlay (`policykit-1`
is not installed; `pkexec` satisfies the alternative). Because the dependency was already
present, the normal `dpkg -i` path was the documented, permitted path and was used without
`--force-*`, `apt-get -f` or any bypass.

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
| T8 | Build the `.deb` 0.53.0 (BPF objects included); fix unit paths found by E2E; rebuild after review fixes | T5 | `packaging/linux/*`, `scripts/linux/package.sh`, `src/Axiom.Infrastructure.Linux/Systemd/SystemdUnit.cs` | **done** — revision-3 artifact `35433682…` from `dc2d9cd`; packaged scripts byte-verified before the 23:02Z live install (§7.2) |
| T9 | Linux package workflow (artifact only, provenance handoff) | T8 | `.github/workflows/linux-release.yml` | **done** — downloadable artifact + `PROVENANCE.txt`; no release attachment |
| T10 | Guest E2E: install, service, doctor, IPC, canary, restart, remove, purge | T8 | – | **done for 0.53 + 0.59** — 0.53 revision 3 (§7.2) and the 0.59.0 artifact (§13): normal `dpkg -i`, all-pass doctor, 4/4 BPF, IPC, 0/10 canary slips, restart durability, remove/purge, migration, coexistence, local TLS DoH. Not covered: OS resolver redirect, GUI, RPM/arm64, Windows runtime |
| T11 | Independent final review of the integrated diff against this plan | T6,T8 | – | **done (local) for `47c39da`**; **not done for `126de46`** (subagent depth limit). Approval covers only the local 0.53 commit/artifact; any later change reopens review |
| T12 | Linux release automation: local build + handoff to the approved release pipeline | T8 | `.github/workflows/linux-release.yml`, `scripts/linux/package.sh` | **partial** — the local `.deb` and a workflow artifact (with checksums/provenance) are ready for an approved release workflow. Attaching the asset to a public GitHub release is **not implemented** and needs a separate gated task with release-write permission. |
| T18 | Refresh the baseline to v0.59.0 and reconcile the shared 0.54 fixes | T2 | merge commit `126de46`; `src/Axiom.Service/PrivacyShield*`, `src/Axiom.Service.Hosting/Dns/IPrivacyDnsPlatform.cs`, `src/Axiom.Infrastructure.Windows/Dns/WindowsPrivacyDnsPlatform.cs`, `src/Axiom.Service/Platform/ServicePlatform.Windows.cs`, `src/Axiom.UI.Avalonia/*` | **done (unreviewed)** — v0.59.0 merged; portable/Linux suites green (§13). Independent review pending |
| T19 | Rename the Linux package to `axiom-firewall` and protect the old package's data | T18 | `packaging/linux/debian/control.in`, `nfpm.yaml.in`, `debian/postinst`, `scripts/linux/package.sh`, `.github/workflows/linux-release.yml`, `docs/LINUX_PACKAGING.md` | **done** — normal install, cross-version upgrade from approved 0.53.0, old-record purge, coexistence with a stand-in archive `axiom` package (§13) |
| T20 | Verify Privacy Shield DoH transport without mutating the OS resolver | T18 | – | **partial** — local TLS DoH proof (TLSv1.3 POST `/dns-query`, answer, untrusted-cert failure, failover) with the system resolver untouched. OS redirect/restore on port 53 remains blocked (§13.4) |

### Worker-ready prompts

Each task is bounded to its `Owned files`; nobody edits outside them without updating this table.

- **T7 (Unix process audit).** "In the reconciliation worktree, add a Linux process-start source
  behind the existing `IProcessStartSource` seam, register it in
  `ServicePlatform.ConfigureProcessSpawnAudit` on Unix, keep the Windows WMI path unchanged, and add
  tests that run on `net10.0`. Do not touch DNS, packaging or the UI. Acceptance: `dotnet build`
  for both TFMs, `Axiom.Core.Tests` process-audit tests pass, new test proves a spawn row is written
  and the file is `0600`."
- **T10 (guest E2E).** Done for revision 3 (§7.2). If rerun: "Boot `run/axiom-test-run.qcow2`
  restricted, install the approved `axiom_0.53.0_amd64.deb`, capture `systemctl status axiomd`,
  `axiomd --doctor`, capabilities over IPC, `pkaction`, `resolvectl status` before and after
  start/stop, a narrow local block, restart with a pending rule, uninstall, and a clean purge.
  Never change the guest's upstream resolvers by hand and never touch host DNS or the firewall.
  Store logs under `/tmp/opencode/axiom-recon-live-final-20261115/`."
- **T11 (final review).** Done locally: the reviewer approved `47c39da` + `35433682…` and must not
  be read as release approval. Any later code/package change reopens the review. The reviewer
  should read this plan and `git diff 5de2d636..<final commit>` plus the package manifest, confirm
  each task's acceptance evidence exists, flag any Windows semantic change not listed in §4, and
  re-check §12 findings 1–10. Do not approve the release-upload gate.
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
- Maintainer scripts: `postinst` → disarms the replaced old `axiom` package's purge script (only when
  it carries our marker lines; both `AXIOM_ROOT`-prefixed and older spelled-out forms) and runs
  `axiomd --install-service` (stages `/usr/libexec/axiom`, writes the unit; an unconfirmed stop
  refuses the replacement); `prerm` → `--uninstall-service`, detaches its own BPF pins only after
  `bpftool` proves no attachment (strict JSON: blank/`[]` means none, otherwise a complete array of
  objects with a non-zero uint32 `id` and decoded string `name` is required), keeps `/var/lib/axiom`
  on an unknown/failed state; `postrm remove|purge` → deletes the unit/image/run dir only after a
  readable `inactive`/`failed` stop state, otherwise keeps them (and on purge the data/logs) and
  fails; `purge` deletes state after that confirmation. The same stop rule is in RPM `%postun`.
- Hard dependencies include `nftables`, `polkitd | policykit-1`, `pkexec | policykit-1`, `systemd`,
  `libbpf1`, `libssl3t64 | libssl3`, ICU and the X11/font stack from `dpkg-shlibdeps`. The pin
  parser uses POSIX awk from the base system (`mawk` Priority: required on Debian/Ubuntu, `gawk` in
  Fedora's core group); python/jq are not used, and a missing awk keeps the pins and fails removal.
- **Current artifact (revision 4, local only):** `axiom-firewall_0.59.0_amd64.deb`,
  64,311,868 bytes,
  `sha256 a09a88d902e54faaf34c0f3b1887815f442be4b70859610643e3915498666824`, built from `126de46`
  (`.deb` at `/tmp/opencode/axiom-recon/build/linux/`; copy, `SHA256SUMS.txt`, `PROVENANCE.txt`,
  test logs and guest evidence in `/tmp/opencode/axiom-production-readiness-20261115/`). It contains
  506 entries; the four packaged shell scripts hash-match the repository files and were
  `cmp`-verified before the guest install. `Package: axiom-firewall`, `Version: 0.59.0`,
  `Conflicts`/`Replaces: axiom (<< 1000)`. **No independent review of this commit yet.**
- **Prior approved artifact (revision 3; superseded for delivery by revision 4):**
  `axiom_0.53.0_amd64.deb`, 63,039,852 bytes,
  `sha256 3543368250a5e1c238ef18364e33acf0a2834f39d428ee62ecd530edece43c5c`, built from `dc2d9cd`,
  approved locally. It remains the only copy of the previous baseline and was used as the *old*
  package in the revision-4 cross-version upgrade test; do not ship it (the `axiom` name collides
  with the archive package).
- **Superseded, not deliverable:** `ce966fa9…` (revision 2, 63,040,292 bytes, 506 entries, build
  `821237d`; `/tmp/opencode/axiom-recon-review-fixes/`) is the artifact rejected for the two HIGH
  blockers (fake JSON acceptance, postrm ignoring an unconfirmed stop). Keep it as evidence; do not
  ship or install it. `919682798343def69ffcc07661700c12992ab77b2ba2927b035e26f8b8170d63`
  (`/tmp/opencode/axiom-linux-release-20261115/`, 63,032,704 bytes, 505 entries, build `4e77777`)
  is the earlier rejected artifact. The `ac9e42d7…` build (merge `3252623`) is also superseded
  (226/NAMESPACE unit abort).
- Integrity checklist: `dpkg-deb -I` shows Version 0.53.0/amd64; 506 entries; `sha256sum` matches
  `SHA256SUMS.txt`; every entry is root/root; packaged script hashes match the repo; polkit XML
  parsed by `package.sh`; desktop entry validated; no `.pdb`, no `libcoreclrtraceptprovider.so`.
- Not done: signing (no key authorised), `lintian` (not installed), RPM (no runtime test), x86-64
  baseline other than Ubuntu 24.04, arm64.

### 7.1 Guest E2E (second run, 2026-11-15T22:21Z, Ubuntu 24.04.5, kernel 6.8.0-147, existing disposable overlay)

This run exercised **revision 2 (`ce966fa9…`)**, not the revision-3 artifact. It is kept as
historical evidence; revision 3 was later installed and exercised in §7.2, including the new
postrm stop confirmation and strict BPF JSON pin path (success paths; the failure paths remain
unit/fake-runner tested). The overlay was booted **restricted** (`no default route`, loopback SSH
only). No provisioning, dependency install, DNS/firewall change or egress was performed;
`pkexec` was already present.

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

### 7.2 Guest E2E for the approved revision-3 artifact (2026-11-15T23:02Z–23:06Z)

Existing disposable overlay `/var/lib/axiom-test-lab/run/axiom-test-run.qcow2`, booted with
`bin/start-restrictedtest.sh` (loopback SSH only, no default route). Ubuntu 24.04.5, kernel
6.8.0-147, uid 1000. No provisioning, egress, dependency install, resolver or firewall change.
Evidence: `/tmp/opencode/axiom-recon-live-final-20261115/` (EVIDENCE.md plus raw command logs).

Artifact: `/tmp/opencode/axiom-recon-packagefix-20261115/axiom_0.53.0_amd64.deb`, 63,039,852
bytes, `sha256 35433682…`. Host and guest `sha256sum` both matched; the four packaged scripts and
`/opt/axiom/bpf-pins.sh` were `cmp`-identical to the repository bytes before install.

| Step | Result |
|---|---|
| Pre-state | no axiom package; `ii pkexec 124-2ubuntu1.24.04.4` + `polkitd`; `axiomd` inactive/not-found; no Axiom dirs, pins, nft table or process; resolver stub symlink `ebdf5602…`; restricted route |
| `sudo dpkg -i /tmp/axiom-final.deb` | `DPKG_RC=0`, `Setting up axiom (0.53.0)`, `Installed and started axiomd.service`; **no `--force`/`apt -f`/dependency install** |
| Service | `active`, `enabled`, `NRestarts=0`, unit `systemd-analyze verify` clean, socket root 0666; `--doctor` **all checks passed**, BPF 4/4 pins, CO-RE verified |
| BPF | programs `axiom_connect4/6`, `axiom_sendmsg4/6` attached at `/sys/fs/cgroup`; pins and maps under `/sys/fs/bpf/axiom` |
| Desktop/polkit | desktop entry and `/opt/axiom/Axiom` installed; `com.axiom.firewall.install` present, `auth_admin`. No GUI run (no display); guest lacks `desktop-file-validate` (host build check only) |
| IPC (uid 1000) | `capabilities` 0.53.0, `firewallWrites:false`; `serviceHealth`, `privacy.status` (disabled, 0 queries), `protection.status`, `rules.query` (verified), `snapshot`; unknown command rejected, not executed |
| Canary (`canary.sh unscoped --count 10`) | `connectTimeBlockingProven=True`; curl/python IPv4+IPv6 all `slipped 0/10 blocked 10/10`; rules removed, protection disabled, no netns/residue |
| Restart durability | valid `/opt` rule `applied`, `connectTimeBlockingProven=True`; `systemctl restart` → active, rule still `applied`, doctor `1 rule connect-time proven`, 4/4 pins; then removed |
| `dpkg -r` | `REMOVE_RC=0`; journal: BPF detached and `/sys/fs/bpf/axiom` removed, table removed, deactivated; unit/image/pins/socket gone, `/var/lib/axiom` + `/var/log/axiom` kept |
| `dpkg -P` | `PURGE_RC=0`; state/log/polkit/desktop gone; no package, no process, no pins/table/socket; resolver hash unchanged |
| Resolver/SSH | resolver symlink and hash unchanged pre/post; SSH control up for every command |
| Fault injection | deliberately **not** run live; postrm stop-failure and malformed/absent-bpftool paths stay unit/fake-runner tested against the exact packaged bytes |
| VM/host after | guest powered off cleanly; no QEMU, no port 2222, no axiom process; host resolv.conf hash `a77e3f44…`, nft axiom 0, docker 12 → 12 |

### 7.3 Blocked install record (2026-11-15T16:49Z, for provenance)

The earlier revision-1 install attempt on the same guest stopped because `pkexec` and
`policykit-1` were both absent (`axiom-linux-release-20261115/guest-evidence/blocked-install.txt`).
That evidence is why §5 treats the later `pkexec` provisioning as an unrecorded action, not a
permission. The 23:02Z pass did not repeat that provisioning; it observed `pkexec` already
present and used the normal install path.


## 8. Test evidence (host, revision 4, 2026-11-16T02:0xZ)

`dotnet build Axiom.Portable.slnx -c Release` — 0 warnings, 0 errors, on `126de46`. Logs:
`/tmp/opencode/axiom-production-readiness-20261115/portable-tests.log`.

| Suite | Result |
|---|---|
| Contracts | 157/157 |
| Core | **184/184** — the Windows-path fixtures now run on Linux (`RuleSpecValidator`, agent path rules, normalisation) |
| Persistence | 21/21 |
| Unix | 47/47 |
| Linux | **102/102** — 52 revision-2 + 35 strict BPF-list payloads + missing-awk + 14 Debian/RPM postrm stop cases |
| MacOS | **249/249** — the root-run socket pair now injects peer uid 501, so the non-root cap and read-only policy are exercised |
| McpServer | 34/34 |
| Presentation | **299/299** — upstream 0.54/0.59 additions plus the config-path/wordlist fixes |
| UI.Avalonia | 80/80 |
| **Service.Hosting** | **31/31** — DoH/Rediscovery 27 + 4 release-script framework checks |
| Linux.Nft.Tests | **160/160** — the 7 reviewed BPF tests restored |
| Desktop.Avalonia.Linux.Tests | 51/51 |

`Axiom.Portable.slnx` itself does not include `Linux.Nft.Tests`; it was run separately. Revision-3
counts (Contracts 156, Presentation 294) are superseded by this run. The earlier "14 Core / 7
Presentation / 2 MacOS pre-existing failures" claim stays withdrawn: the failures were a mix of a
Linux-only product bug and platform-specific fixtures, fixed rather than excused.

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

- **Integration gate (revision 4):** merge commit `126de46` exists, both TFMs compile, portable
  and Linux suites are green (§8); portable locked restore passes; Windows cross-builds pass. Full
  solution locked restore is Windows-host-only (`NETSDK1100`).
- **Review gate (revision 4 OPEN):** the review of `5de2d636..7fad752` rejected eight findings
  (fixed in `821237d`); the review of `400d4a9` rejected two more HIGH blockers (fixed in
  `dc2d9cd`); a fresh independent review **approved** `47c39da` and artifact `35433682…`. That
  approval does **not** cover `126de46` or `a09a88d9…`; no independent review of revision 4 was
  possible in this run (subagent depth limit). Do not present revision 4 as reviewed.
- **Install gate (passed on 0.53 and 0.59):** clean normal `dpkg -i` on the disposable Ubuntu
  24.04.5 guest (`pkexec` already present, no provisioning), service enabled/active, `--doctor`
  all checks passed, BPF 4/4 and CO-RE verified on guest kernel 6.8, IPC, 0/10 canary slips
  IPv4+IPv6, restart durability, remove/purge; resolver untouched; clean guest/host. Revision 4
  adds cross-version upgrade from the approved 0.53.0 `axiom` package with rule/data preservation
  and an old-record purge, coexistence with a stand-in archive `axiom` package, and a local-TLS
  DoH proof (§13).
- **Still unproven after revision 4:** Privacy Shield OS redirect/restore on port 53 (only the
  DoH transport is proven), GUI, RPM/Fedora, arm64, Windows runtime/WPF/locked restore,
  guest failure injection for the installer/postrm stop path or a live malformed/absent bpftool
  output (unit/fake-runner only).
- **Release gate (not authorised):** no upload, tag, release notes, signing, push or deployment.
  T12 only prepares local/workflow artifacts for an approved release workflow.
- Known limits to publish with any artifact: Ubuntu 24.04 x64 only; WMI/process-start audit absent
  on Linux; `.rpm` unbuilt/untested; GUI walkthrough not performed; Privacy Shield redirect not
  exercised live; no signing; Windows runtime not executed on this host; the pin parser depends on
  base-system POSIX awk and fails safe (keeps pins) without it.
- DoH transport is now proven live over local TLS, but `privacy.status` alone is not proof of an
  encrypted query; the local server log with TLS version/cipher is the evidence.

### 10.1 Remaining worker-ready tasks (not started; each needs its stated permission)

| ID | Task | Gate/permission | Acceptance |
|---|---|---|---|
| T7 | Unix process-start source for F-19 | none (code only); **deferred** | Linux `IProcessStartSource` behind the existing seam, Windows WMI unchanged, `net10.0` tests prove a spawn row and `0600` file. Not required for the shipped surface; do not claim WMI parity |
| T13 | Cross-version upgrade | **done** | Approved 0.53.0 `axiom` (data + applied rule) → 0.59.0 `axiom-firewall`: rule/data preserved, doctor passes, old `axiom` purge leaves data and the service active; stand-in archive `axiom` 20170501 stays intact |
| T14 | GUI walkthrough on Linux | guest display/provisioning permission (no display; no Xvfb installed) | Launch `/opt/axiom/Axiom` under Xvfb/desktop, navigate overview/rules/history/settings, no render error; separate from the headless desktop-file check already done |
| T15 | Privacy Shield OS redirect/restore | **explicit permission to change the disposable guest resolver** (port 53) | Enable Privacy Shield on port 53 against a controlled DoH endpoint, prove redirect and fail-safe restore on stop/crash/uninstall, restore the pre-test resolver exactly. DoH transport itself is proven (§13.4); redirect/restore is not |
| T16 | RPM, arm64, Windows runtime | build host with `nfpm`/rpm; arm64 hardware or emulation; Windows host | RPM install/upgrade/erase with the mirrored scriptlets; arm64 `.deb` boots and doctor passes; `Axiom-Setup.exe`/service run on Windows. No claim from cross-compilation alone |
| T17 | Windows locked restore / WPF tests | Windows host (host here cannot run WPF, `NETSDK1100`) | `dotnet restore Axiom.sln --locked-mode`, `Axiom.UI.Tests` and Windows service tests pass on Windows; record RID lock graphs |
| T21 | Independent review of `126de46` + `a09a88d9…` | fresh-context reviewer (this run hit the subagent depth limit) | reviewer reads `3d7ccf1..126de46`, the packaging migration and the DoH test; confirms no Windows semantic change, no data-loss path, preserved safety fixes intact; findings fixed or accepted in writing |

## 11. Where the evidence lives

- Worktree: `/tmp/opencode/axiom-recon` (branch `recon/linux-main-0.59.0`, HEAD `126de46`;
  previous branch `recon/linux-main-0.53.0` at `3d7ccf1`).
- Revision-4 artifact + `SHA256SUMS.txt` + `PROVENANCE.txt` + host/guest logs + local DoH evidence:
  `/tmp/opencode/axiom-production-readiness-20261115/` (`.deb` `a09a88d9…`, 64,311,868 bytes,
  `REPORT.md`).
- Revision-3 artifact + `SHA256SUMS.txt` + `PROVENANCE.txt` + build/test logs (prior baseline):
  `/tmp/opencode/axiom-recon-packagefix-20261115/` (`.deb` `35433682…`, 63,039,852 bytes).
- Revision-3 live install/remove evidence (23:02Z–23:06Z): 
  `/tmp/opencode/axiom-recon-live-final-20261115/` (`EVIDENCE.md`, host/guest pre/post,
  install, doctor, IPC, canary, restart, remove/purge, serial tail).
- Revision-2 artifact + guest logs (superseded, evidence only):
  `/tmp/opencode/axiom-recon-review-fixes/` (`.deb` `ce966fa9…`, 63,040,292 bytes).
- Rejected revision-1 artifact (evidence only, do not ship):
  `/tmp/opencode/axiom-linux-release-20261115/`.
- Pre-merge control worktree: `/tmp/opencode/axiom-baseline` (detached `a4275f4`).
- Prior reports (Nov 14, historical): `/tmp/opencode/axiom-review-dns-20261114/REPORT.md`,
  `/tmp/opencode/axiom-review-closeout-20261114/REPORT.md`,
  `/tmp/opencode/axiom-review-parser-validation/REPORT.md`.
- Published (pre-existing): PR #276 comment `#issuecomment-6883150435`; wiki
  `projects/axiom/linux-e2e-validation-2026-11-12#review-follow-up-2026-11-14`; issue #150
  revision-3 comment `#issuecomment-6902932272`.

## 12. Review findings fixed in `821237d`, plus revision-3 blockers in `dc2d9cd`

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
| 9 | `packaging/linux/bpf-pins.sh` accepted any bracketed text as JSON: `[{}]`, `[broken]`, invalid id 0 removed pins, and an escaped `axiom_connect\u0034` was not detected while still attached | Replaced the substring check with a strict JSON parser (base-system POSIX awk, no python/jq): blank stdout or `[]` is bpftool's real empty answer; otherwise the document must be an array of objects with a non-zero uint32 `id` and a decoded string `name`; malformed/non-array/non-object/missing/duplicate/wrong-typed/unknown, bad escapes, trailing data and invalid ids fail and keep the pins. Missing awk also fails safe. RPM `%preun` inherits it | 35 payload cases (all listed counterexamples incl. escaped names, id 0/negative/string/overflow/leading zero, valid foreign, blank/`[]`) + missing-awk test; revision-2 guest smoke did not cover these counterexamples and is not counted |
| 10 | `debian/postrm` and `rpm/postremove` ignored `systemctl disable --now` failure and deleted the unit and `/usr/libexec/axiom`, even if the daemon was still active/unknown | Delete only after a confirmed stop: `disable --now` plus a readable `is-active` of `inactive`/`failed`; still-active, timeout/unknown, missing systemctl or missing state keep the unit, image, run dir and (on purge) data/logs, and fail the removal. Upgrades still do nothing; RPM mirrored; test-only `AXIOM_MAINTAINER_TEST_ROOT` relocates paths | 14 fake-systemctl cases (Debian remove/purge success, active, timeout/unknown, missing systemctl, failed-disable-but-inactive, absent unit, no systemd, upgrade; RPM erase success/active/upgrade) against the exact packaged scripts; no guest E2E for revision 3 |

## 13. Revision 4 — v0.59.0 parity, package rename, cross-version and DoH evidence

Measured 2026-11-16T01:2xZ–02:1xZ UTC on the same host and disposable Ubuntu 24.04.5 overlay
(kernel 6.8.0-147). No push, merge, tag, release, upload, signing, provisioning or resolver change.

### 13.1 Delta after the approved 0.53 target (recorded, not chased further)

`5de2d636..28918945` (v0.53.0 → v0.59.0):

| Release | Content | Relevance to Linux |
|---|---|---|
| 0.54.0 | module prerequisites/repair, loopback probes, adapter DNS 127.0.0.1, feed resilience, memory reduction | **shared service/UI code used by Linux — merged** |
| 0.55.0 / 0.56.0 | brand assets and icons | UI assets; merged as upstream |
| 0.57.0 | Avalonia theme redesign | shared UI; merged as upstream |
| 0.58.0 | docs screenshots | docs only |
| 0.59.0 | brand/nav/dashboard polish | shared UI; merged as upstream |

Upstream PR #276 advanced independently to `1827deb` with `5159056` (doctor counts), `788c0795`
(detach logging), `a66fb55` (unreadable bpftool is unknown), `6504b97` (optional resolver paths),
`78a2384` (rename), `1827deb` (old-package purge disarm). This branch already carried reviewed
equivalents of the first four (from the `b6b6049` review series). The rename and disarm were
**ported**; the divergent implementations of the BPF unknown-state fixes stay as the reviewed
`b6b6049` code (Nft tests 160/160, live canary clean). A future PR refresh must reconcile both
implementations deliberately, not by blind merge.

### 13.2 Package rename and migration

- `Package: axiom-firewall`, `Conflicts`/`Replaces: axiom (<< 1000)` in DEB and `conflicts: axiom < 1000`
  (no `Obsoletes`) in the RPM mapping. Paths, `axiomd.service` and `com.axiom.firewall` unchanged.
- `postinst` disarms `/var/lib/dpkg/info/axiom.postrm` only when it carries our markers, accepting
  both the 0.53-era `AXIOM_ROOT`-prefixed paths and the older spelled-out paths. The archive
  `axiom` package does not match these lines and is untouched.
- Guest results: a stand-in distro `axiom` 20170501 package stayed installed with its files intact
  across `axiom-firewall` install and purge; the approved 0.53.0 `axiom` package (with one applied
  rule) upgraded to 0.59.0 keeping `managed-rule.json`, enforcer generation and the applied rule;
  `dpkg --purge axiom` removed only the old record (data marker still present, service active).
- The `nfpm` RPM path is still unbuilt and untested; no Fedora claim.

### 13.3 Host gates (revision 4)

Portable suites: Contracts 157, Core 184, Persistence 21, Unix 47, Linux 102, MacOS 249, MCP 34,
Presentation 299, UI.Avalonia 80, Service.Hosting 31; separately Linux.Nft 160 and
Desktop.Avalonia.Linux 51. All pass. `Axiom.Portable.slnx --locked-mode` restore passes; the full
solution restore fails `NETSDK1100` on Linux (WPF), and with `EnableWindowsTargeting=true` fails
`NU1004` for the Windows projects (stale lock graphs). Both need a Windows host (T17).
Windows cross-builds (Windows infrastructure, service `net10.0-windows`, Windows Avalonia desktop,
Service.Tests) pass; no Windows runtime is claimed.

### 13.4 Privacy Shield DoH — what is proven, what is not

Local TLS server + temporary test CA on the disposable guest; **no OS resolver change**. The
resolver was enabled on loopback port 5353 with an explicit DoH upstream:

- trusted cert: TLSv1.3 / `TLS_AES_256_GCM_SHA384`, `POST /dns-query`, valid A answer
  (`203.0.113.7`), `queries 1 errors 0`;
- untrusted cert only: SERVFAIL, `errors 1`, no answer and no plaintext fallback (the target has
  no plain endpoint);
- two-target list with untrusted first and trusted second: answer from the trusted target (the
  untrusted handshake is rejected, then failover succeeds);
- cleanup: privacy disabled, test CA/drop-in removed, daemon restarted, `/etc/resolv.conf` symlink
  and sha256 unchanged, doctor passes.

Not proven: pointing the OS resolver at Axiom on port 53, redirect/restore on stop/crash/uninstall,
or any external DNS egress. That needs explicit permission to change the disposable guest resolver
(T15).

Test-harness note: the unit has `PrivateTmp=yes`, so `SSL_CERT_FILE` must point outside `/tmp`
(used `/etc/axiom-test-ca.crt`, removed after). Before that, the same config returned SERVFAIL with
no TCP attempt — that was the missing CA path, not a product DoH bug.

### 13.5 Review and next gates

`126de46` and `axiom-firewall_0.59.0_amd64.deb` (`a09a88d9…`) are **built and locally live-tested,
not independently reviewed**. The parent/next session should run T21 with a fresh-context reviewer.
Remaining product gates: T14 GUI, T15 OS redirect/restore, T16 RPM/arm64/Windows runtime, T17
Windows WPF/locked restore, T7 Linux process audit (deferred, not parity).

### 13.6 Product behaviour observed (not filed as a bug)

`protection.disable` removes managed rules; the canary script calls it on cleanup, so rules
applied before a canary run are gone afterwards. Re-enable protection and re-apply. This is
consistent with the existing protection lifecycle, not with a silent claim of rule persistence.

Revision 5 (2026-11-16T03:2xZ UTC, single builder): the T21 review approved the local
`126de46` artifact for what it tested but left four live findings. They are fixed in local commit
`cbff83a` and rebuilt as `axiom-firewall_0.59.0_amd64.deb` sha256
`fc78a518e686c19eae7a9340344d12cc240bea426c2cdb3e63e7cdfcd71bfac0` (64,323,164 bytes).
The old `a09a88d9…` artifact is **superseded for new testing**, not "bad"; its approval stays
scoped to `126de46`. Fresh independent review of `cbff83a`/`fc78a518` is required before any new
approval claim. No push/merge/tag/release/upload/signing; host DNS/network/firewall untouched.

## 14. Revision 5 — four finding fixes and live re-test

Evidence root: `/tmp/opencode/axiom-e2e-fixes-20261115/` (`REPORT.md`, `PROVENANCE.txt`,
`SHA256SUMS.txt`, test/build logs, guest logs, `gui/*.png`).

| # | Finding | Fix | Fresh test evidence |
|---|---|---|---|
| 1 | GUI-LOW stale "Writes are disabled…" after shield enable, at `FirewallPageViewModel.cs:283` | The result line starts empty; the live hint derives from the service write gate (`WritesEnabled`) and `ShieldEnabled`. A shield-on/closed-gate state gets its own "has not opened the write gate" hint. Same stale initial string removed from the WPF `FirewallRulesViewModel`. Adjacent header bug: `ShellViewModel.RefreshStatus` now recomputes `Overview.StatusText` from `_protection.WriteGateOpen`, so the global header cannot stay "Read-only inventory" while the footer says SHIELD ON | UI.Avalonia 90/90, including enable/disable/auth-failure transitions, enabled-but-gate-closed, and PropertyChanged notifications; live 1280x800 screenshots `gui/nc-shield-on-final.png`, `gui/nc-final2.png` |
| 2 | GUI-MEDIUM default 1460x900 at -90,-50 on 1280x800 | `MainWindow` clamps the preferred size to the current screen working area at its DPI scale, centers inside it, and uses `ScreenFromWindow` after open (the X11 screen list is not available in the constructor) | Layout theory (1280x800, 1024x768, 800x600, 1920x1080, 2x HiDPI) + headless fit test; live Xvfb: 1280x800 at +0+0, `gui/small-default-1280x800.png` |
| 3 | TEXT-LOW hardcoded DoH port 443 at `PrivacyShieldView.axaml:57` / `DnsProxyServer.cs:248` | Both Avalonia and WPF copy say HTTPS and that the port comes from the DoH URL; resolver detail drops the fixed port. No functional DNS change | Service.Hosting 34/34 (default 443, custom 8443, plain DNS); live custom 8443 status `UPSTREAM …:8443…`, detail "encrypted with DoH (HTTPS)", TLS1.3 answer, `gui/privacy-active-8443.png`, `guest-doh-config.txt` |
| 4 | DNS-MEDIUM 10 s resolver outage after SIGKILL | `RestartSec=10` -> `2`; explicit `StartLimitIntervalSec=60`, `StartLimitBurst=5`; no resolver reset hook, no plaintext fallback, backup/pending untouched | Linux 102/102 with unit restart/start-limit assertions; live single SIGKILL: process dead 0.007 s, 22 raw UDP queries failed during the gap, first recovered answer 2.692 s after death, stable 2.724 s, backup still 10.0.2.3, `guest-crash-definitive.txt` |

Other revision-5 results: Linux.Nft **160/160 fresh** and Desktop.Avalonia.Linux **51/51 fresh**
(they were carried forward at `126de46`); Contracts 157, Core 184, Persistence 21, Unix 47,
MacOS 249, MCP 34, Presentation 299, Hosting 34, UI.Avalonia 90. Windows cross-builds (WPF UI,
Avalonia Windows desktop, Windows service) 0 errors. Packaged maintainer scripts and
`bpf-pins.sh` are byte-identical to the approved baseline; only binaries changed.

Guest acceptance against `fc78a518`: normal `dpkg -i` (RC 0), doctor all pass, 4/4 BPF pins,
`table inet axiom generation 1`; GUI 1280x800 on-screen; shield-on hint and header truthful;
Privacy Shield custom 8443 E2E; UI disable restore; clean stop/start restore and re-redirect;
`dpkg -P` while redirected restored 10.0.2.3 then removed package/unit/opt/state/run/nft
table/BPF pins/backup; test CA/drop-in/server removed; guest pre/post resolver state equals
(`ebdf5602…`, modes 777, only `127.0.0.53/.54:53`, `bccfe813…`). Authorized GUI tools remain. A second clean boot re-installed the final artifact, re-checked shield enable and the 1280x800 window (`gui/nc-shield-on-final-artifact.png`), then purged it and left the guest resolver untouched.

Residual: a persistent crash loop still ends in a fail-closed outage once the start limit trips
(systemd stops retrying; manual repair needed). The measured 2.69 s applies to a single crash on
this VM, not to every host. This is not production readiness: real Wayland/tray, polkit denial,
public-DoH egress, Windows runtime, Fedora/RPM, arm64, signing, lintian and locked restore remain
open, and no broad Windows parity is claimed.

Revision 6 (2026-11-16T04:2xZ UTC, single builder): two review nits and the stale unit docs are
fixed in local `d90c9ff48d121f6cacf99c0672140973ebd30a18`, rebuilt as
`axiom-firewall_0.59.0_amd64.deb` sha256
`06d8320192c2329eef4b8f3b7b6a55395758dbb6f37ec15b98495c906233d953` (64,324,056 bytes). The prior
artifact (`fc78a518…`) is preserved unmodified under the new evidence root. Fresh independent
review of `d90c9ff` / `06d832…` is required before any approval claim.

| Finding | Fix | Fresh evidence |
|---|---|---|
| GUI ceil overshoot at fractional DPI | `MainWindow` caps the `ceil()`ed pixel size to the working area before converting back to DIPs; the 900x600 floor is lowered only when the screen cannot fit it | UI.Avalonia 94/94; real Xvfb: 1280x800@1x = 1280x800 at +0+0, 1280x800@1.5 = 1280x800 at +0+0 (no 1350x900 min overflow), 1920x1080@1.25 = 1825x1080 at +47+0; negative-origin and large-screen theories |
| WPF hint stale/failed-probe enabled | Hint is now open / known-closed / unknown; a failed probe clears `WritesEnabled`, sets `WriteGateKnown=false`, and never claims "by design" for an unread gate. `WritesEnabled` remains the service write-gate bit only | `tests/Axiom.UI.Tests/FirewallRulesWriteGateTests.cs` cross-builds 0 warnings/0 errors; runtime **blocked** (no WindowsDesktop 10.0.0 on this Linux host), not claimed as pass |
| Docs still showed `RestartSec=10` | Both unit examples now show `RestartSec=2`, `StartLimitIntervalSec=60`, `StartLimitBurst=5`; no other doc claims changed | targeted doc edit |

Other gates checked this pass:

- Portable locked restore exits 0 with a non-empty stdout log; all 34 lock hashes unchanged
  (aggregate `197d6b93…` before and after).
- Full-solution `restore --locked-mode -p:EnableWindowsTargeting=true` still fails `NU1004`
  (stale Windows lock graphs: a new `Axiom.Service.Hosting` project reference and changed Setup
  runtime identifiers). This is not a portable-solution failure. Non-locked restore with the
  same flag succeeds and the full solution then builds 0 warnings / 0 errors; Windows tests
  remain blocked at runtime.
- `lintian` is absent and was not installed. Non-privileged `pkexec` without a controlling
  terminal fails before any prompt (exit 127); this is the no-agent path, not a denial/cancel
  proof.
- Guest smoke on the new artifact: clean `dpkg -i` RC 0, correct `--doctor` all checks passed,
  nftables generation 1, 4/4 BPF pins; Xvfb GUI 1280 and fractional sizes on-screen; Network
  Control READ-ONLY hint, SHIELD ON hint after enable, READ-ONLY after disable; clean `dpkg -P`
  RC 0 with package/unit/state/nft/pins removed and guest resolver hash unchanged. VM powered
  off; baseline unchanged; host resolver unchanged.
- Harness note: the first smoke used `axiomd doctor` (missing `--`), which starts a second
  foreground daemon and caused generation churn. The retained old artifact reproduced the same
  churn; after a clean guest reboot the correct `--doctor` passed. Not a product change.

Evidence root: `/tmp/opencode/axiom-dpi-wpf-fixes-20261115/` (`REPORT.md`, `PROVENANCE.txt`,
`SHA256SUMS.txt`, test/build logs, guest logs, `gui/*.png`). Remaining gates unchanged: fresh
independent review, Windows WPF runtime, E2E WPF behaviour, lintian, full-solution locked
Windows restore, Fedora/RPM, arm64, signing, real Wayland/tray, polkit denial UX, OS DNS
redirect/restore (unchanged code, not retested). Not production readiness; no broad Windows
parity claim.
