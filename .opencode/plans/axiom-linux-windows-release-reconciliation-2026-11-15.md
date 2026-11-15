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
| T10 | Guest E2E: install, service, doctor, IPC, canary, restart, remove, purge | T8 | – | **done for revision 3** — normal `dpkg -i`, all-pass doctor, 4/4 BPF, IPC, 0/10 canary slips, restart durability, remove/purge on Ubuntu 24.04.5 (§7.2). Not covered: Privacy Shield live redirect, GUI, cross-version upgrade, live fault injection |
| T11 | Independent final review of the integrated diff against this plan | T6,T8 | – | **done (local)** — independent review approved `47c39da` and artifact `35433682…`; approval covers the local commit/artifact only, not a release |
| T12 | Linux release automation: local build + handoff to the approved release pipeline | T8 | `.github/workflows/linux-release.yml`, `scripts/linux/package.sh` | **partial** — the local `.deb` and a workflow artifact (with checksums/provenance) are ready for an approved release workflow. Attaching the asset to a public GitHub release is **not implemented** and needs a separate gated task with release-write permission. |

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
- Maintainer scripts: `postinst` → `axiomd --install-service` (stages `/usr/libexec/axiom`, writes
  the unit; an unconfirmed stop refuses the replacement); `prerm` → `--uninstall-service`,
  detaches its own BPF pins only after `bpftool` proves no attachment (strict JSON: blank/`[]` means
  none, otherwise a complete array of objects with a non-zero uint32 `id` and decoded string `name`
  is required), keeps `/var/lib/axiom` on an unknown/failed state; `postrm remove|purge` → deletes
  the unit/image/run dir only after a readable `inactive`/`failed` stop state, otherwise keeps them
  (and on purge the data/logs) and fails; `purge` deletes state after that confirmation. The same
  stop rule is in RPM `%postun`.
- Hard dependencies include `nftables`, `polkitd | policykit-1`, `pkexec | policykit-1`, `systemd`,
  `libbpf1`, `libssl3t64 | libssl3`, ICU and the X11/font stack from `dpkg-shlibdeps`. The pin
  parser uses POSIX awk from the base system (`mawk` Priority: required on Debian/Ubuntu, `gawk` in
  Fedora's core group); python/jq are not used, and a missing awk keeps the pins and fails removal.
- **Current artifact (revision 3, approved locally, live-installed):** `axiom_0.53.0_amd64.deb`,
  63,039,852 bytes,
  `sha256 3543368250a5e1c238ef18364e33acf0a2834f39d428ee62ecd530edece43c5c`, built from `dc2d9cd`
  (`.deb` at `/tmp/opencode/axiom-recon/build/linux/`; copy, `SHA256SUMS.txt`, `PROVENANCE.txt` and
  test logs in `/tmp/opencode/axiom-recon-packagefix-20261115/`). It contains 506 entries; the four
  packaged shell scripts hash-match the repository files (see `package-verify.log`) and were
  re-verified before the 23:02Z install (§7.2). Independent review approved the local commit and
  this artifact; it is not a release.
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


## 8. Test evidence (host, revision 3, 2026-11-15T22:4x-22:5xZ)

`dotnet test` per project in Release on the final commit `dc2d9cd`. This run was as **root** on
Linux (host kernel 7.0.0-38). Logs: `/tmp/opencode/axiom-recon-packagefix-20261115/`.

| Suite | Result |
|---|---|
| Contracts | 156/156 |
| Core | **184/184** — the Windows-path fixtures now run on Linux (`RuleSpecValidator`, agent path rules, normalisation) |
| Persistence | 21/21 |
| Unix | 47/47 |
| Linux | **102/102** — 52 revision-2 + 35 strict BPF-list payloads + missing-awk + 14 Debian/RPM postrm stop cases |
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
  (revision 3 counts in §8).
- **Review gate (closed locally, not a release approval):** the review of `5de2d636..7fad752`
  rejected eight findings (fixed in `821237d`); the review of `400d4a9` rejected two more HIGH
  blockers (fixed in `dc2d9cd`). A fresh independent review then **approved** local commit
  `47c39da` and artifact `35433682…`. That approval is scoped to the local commit/artifact; it is
  not a release, merge, signing or publication approval.
- **Install gate (passed on revision 3, 2026-11-15T23:02Z–23:06Z):** clean normal `dpkg -i` with
  the approved artifact on the disposable Ubuntu 24.04.5 guest (`pkexec` already present, no
  provisioning), service enabled/active, `--doctor` all checks passed, BPF 4/4 and CO-RE verified
  on guest kernel 6.8 (object built on host 7.0), IPC, 0/10 canary slips IPv4+IPv6, restart
  durability, `dpkg -r`, `dpkg -P`; resolver untouched; clean guest/host. Still unproven: Privacy
  Shield live redirect/restore (deliberately not exercised), GUI (headless), cross-version
  upgrade, guest failure injection for the installer/postrm stop path or a live malformed/absent
  bpftool output (unit/fake-runner only), RPM/arm64/Windows runtime.
- **Release gate (not authorised):** no upload, tag, release notes, signing, push or deployment.
  T12 only prepares local/workflow artifacts for an approved release workflow.
- Known limits to publish with any artifact: Ubuntu 24.04 x64 only; WMI/process-start audit absent
  on Linux; `.rpm` unbuilt/untested; GUI walkthrough not performed; Privacy Shield redirect not
  exercised on the guest (unit-tested only); no signing; Windows runtime not executed on this host;
  the pin parser depends on base-system POSIX awk and fails safe (keeps pins) without it.
- DoH status is not proof of an encrypted query: the unit tests use fake handlers and a local TLS
  mock can prove the protocol only; no live public DNS query is claimed.

### 10.1 Remaining worker-ready tasks (not started; each needs its stated permission)

| ID | Task | Gate/permission | Acceptance |
|---|---|---|---|
| T7 | Unix process-start source for F-19 | none (code only) | Linux `IProcessStartSource` behind the existing seam, Windows WMI unchanged, `net10.0` tests prove a spawn row and `0600` file |
| T13 | Cross-version upgrade | **two approved Linux artifacts**; none published yet. Do not install the rejected revisions (`ce966fa9…`, `9196827…`, `ac9e42d7…`) | With a prior approved N-1 and the approved 0.53.0 package: `dpkg -i` over N-1 keeps data/rules, replaces the unit/image, service returns active; `dpkg -r`/`-P` still clean. Must not use a rejected build as the baseline |
| T14 | GUI walkthrough on Linux | guest display/provisioning permission (currently no display; installing Xvfb/desktop is out of scope) | Launch `/opt/axiom/Axiom` under Xvfb/desktop, navigate overview/rules/history/settings, no render error; separate from the headless desktop-file check already done |
| T15 | Privacy Shield live DoH + redirect/restore | **explicit permission to change the guest resolver and run a controlled DNS target/egress** | Enable Privacy Shield against a controlled DoH endpoint, prove encrypted transport on the wire, prove redirect and fail-safe restore on stop/crash/uninstall, restore the pre-test resolver exactly. Never claim encrypted DNS from `privacy.status` alone |
| T16 | RPM, arm64, Windows runtime | build host with `nfpm`/rpm; arm64 hardware or emulation; Windows host | RPM install/upgrade/erase with the mirrored scriptlets; arm64 `.deb` boots and doctor passes; `Axiom-Setup.exe`/service run on Windows. No claim from cross-compilation alone |
| T17 | Windows locked restore / WPF tests | Windows host (host here cannot run WPF, `NETSDK1100`) | `dotnet restore Axiom.sln --locked-mode`, `Axiom.UI.Tests` and Windows service tests pass on Windows; record RID lock graphs |

## 11. Where the evidence lives

- Worktree: `/tmp/opencode/axiom-recon` (branch `recon/linux-main-0.53.0`, packaging fixes
  `dc2d9cd`, approved local HEAD `47c39da`).
- Revision-3 artifact + `SHA256SUMS.txt` + `PROVENANCE.txt` + build/test logs:
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
  `projects/axiom/linux-e2e-validation-2026-11-12#review-follow-up-2026-11-14`.

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
