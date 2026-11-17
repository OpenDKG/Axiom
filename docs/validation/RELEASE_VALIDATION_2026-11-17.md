# Release validation and trust — 17 November 2026

This record covers the checks that were run against the installed builds between 0.89.0 and 0.95.0,
the signing decision, and the checks that were deliberately not run. It is evidence, not a
certification.

## 1. In-place upgrade validation (host and isolated VM)

Environment: Windows 11 host and the isolated `Axiom-Win11` VirtualBox VM, standard user `lab`.
Every release was installed with `Axiom-Setup.exe --silent --accept-risk --no-launch`, then the
desktop was started with `--autostart`.

| Check | Result |
| --- | --- |
| Versions installed in sequence | 0.89.0, 0.90.0, 0.91.0, 0.92.0, 0.93.0, 0.94.0 (host and VM) |
| Setup exit code | 0 on each silent install |
| `install.json` version | matches the installed setup on host and VM |
| Desktop and service binaries | matching product version after each install |
| Axiom service state | `Running` after each install |
| Blackbox build marker | `.axiom-blackbox-build` present after each install |
| Enforcement policy | `enabled=true`, 11 agents, 88 rules, 8 protected resources after each install |
| Policy ACL | `%ProgramData%\Axiom\enforcement-policy.json` is SYSTEM-only; a standard user gets `Access is denied` on `Test-Path` (intended) |
| UpgradeDataGuard | "181 intact, 4 restored, 0 smaller than the backup, 0 failed" on the recorded upgrades |
| Privacy Shield data | 699,215 active entries compiled after 0.94.0; sources updated |
| DKG node | came up on 0.93.0/0.94.0 after the launcher workaround: port 9320 open, API 200, 8/8 stability probes; verified-graph sync running |

Limits:

- The VM has carried Axiom state from earlier versions; this is not a pristine OS image test.
- The interactive wizard was not driven; only the silent path and the desktop UI were exercised in
  this cycle. Partial-mode behaviour comes from the installer's own tests, not from this run.
- The host is a development workstation, not a clean machine.

## 2. OS enforcement and Privacy Shield network tests

- Hook-level enforcement is what runs by default: `enforcement.status` reports the policy, but
  `receiptCount`, `hostDenySentCount` and `hostDenyVerifiedCount` stay at 0 because the WFP/OS deny
  path is not enabled. No screenshot or log in this cycle claims an OS-level block.
- `scripts/validate-vm-enforcement.ps1 -ExecuteInIsolatedVm` (WFP OS_DENY_VERIFIED plus rollback,
  Privacy Shield DNS crash/restore, DKG/Blackbox offline reboot recovery) was **not executed**. It
  changes host network enforcement and needs a disposable snapshot and an owner decision on the
  rollback window; running it unattended would risk the lab network without a recovery check.
- The Privacy Shield page continues to state that it is a DNS filter, not a VPN or traffic proxy.

## 3. Signing decision (issues #119 and #289)

**Decision: sign release artifacts with Authenticode through SignPath Foundation, using its
GitHub OIDC integration. Azure Trusted Signing is the paid fallback. Do not use self-signed
certificates and do not put a private key in the repository or in GitHub secrets.**

What gets signed once enrollment is complete:

- `Axiom.Setup.exe`
- `Axiom.Desktop.exe` and `Axiom.Service.exe` inside `Axiom-<version>-win-x64.zip`

How:

1. SignPath Foundation application for the open-source project (requires the public repository and
   the existing CI build as the trusted build system).
2. A signing step in `windows-ci.yml` after the packaging check, using the SignPath GitHub Action and
   OIDC; no long-lived key material in this repository.
3. `SHA256SUMS.txt` remains the integrity check; the signature adds publisher identity and
   SmartScreen reputation over time.

Until that exists, releases stay explicitly unsigned: release notes and the README say so, and the
verification instructions use `certutil -hashfile ... SHA256` against `SHA256SUMS.txt`. SmartScreen
warnings on fresh machines are expected and must not be described as fixed.

Status: decision recorded; enrollment needs the owner's SignPath/org account, so #119 and #289 stay
open until signed artifacts are published.

## 4. Cross-platform status

- macOS (#274, #388, #325) and Linux (#276, #150, #175, #290) remain open ports with their own
  backends (Network Extension, nftables/eBPF). They have no CI gate on the Windows-only runner and
  cannot be validated from this VM. Do not claim platform parity.
- The Windows work in this cycle did not change platform-specific code paths; the IPC split and
  portable contracts stay untouched.
