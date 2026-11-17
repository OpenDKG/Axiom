# AXIOM 1.0 — Phase 7: Windows Release Trust, Signing & Installer Security Audit

> **Baseline:** `v0.32.0` (`Axiom-Setup.exe` 90.97 MB, `Axiom-0.32.0-win-x64.zip` 78.24 MB, `SHA256SUMS.txt`)

> **Update 17 Nov 2026:** signing decision, in-place upgrade evidence and the checks not run are
> recorded in [RELEASE_VALIDATION_2026-11-17.md](RELEASE_VALIDATION_2026-11-17.md).

---

## 1. Current Packaging & Trust Posture

| Requirement | Current Implementation | Observed State | Gap / Action for `1.0` |
|---|---|---|---|
| **Authenticode Signing & SmartScreen** | Unsigned Win32 binaries (`Axiom.Desktop.exe`, `Axiom.Service.exe`, `Axiom.Setup.exe`) | **Not signed (`#119`, `#289`)** — SmartScreen warns on fresh Windows machines | **Recommended free OSS path (zero spend):** Apply to **SignPath Foundation** (`https://signpath.org/terms`) once open-source governance / reproducible build prerequisites in `.github/workflows/windows-ci.yml` are active on GitHub (`CODEOWNERS`, build-from-source release trigger). Never embed private keys in repo or CI secrets. |
| **SHA-256 & Binary Integrity** | `scripts/build-release.ps1` emits `SHA256SUMS.txt`; `SetupInstaller.cs` hashes `Axiom.Desktop.exe` & `Axiom.Service.exe` into `install.json` | **Verified locally (`v0.32.0`)** | Publish `SHA256SUMS.txt` alongside every GitHub Release; include explicit verification steps in release notes. |
| **Setup Payload Integrity** | Embedded Win32 setup payloads under `Axiom.Setup.Payload.*` (`SetupInstaller.ExtractPayloadAsync`) | **Implemented** — setup verifies Desktop + Service presence before writing | Optional future enhancement: embed expected payload manifest SHA-256 table inside `Axiom.Setup` at build time and verify after extraction. |
| **Install Target Safety** | `SetupInstaller.cs` checks `StorageSafety.IsReparsePointInPath(options.InstallDir)` | **Implemented** — refuses junctions/symlinks; aborts if `Axiom.Desktop.exe` is still running | Test interactive install/uninstall/upgrade flows in clean Windows 10/11 VM. |
| **Silent Flag Gate** | `Axiom.Setup` exits with code `2` if `--silent` is passed without `--accept-risk` | **Verified (`v0.32.0`)** | Prevents accidental silent install without explicit risk acknowledgment. |
| **Service Permissions & IPC ACLs** | `ServiceInstaller.Install`, `MachineStateSecurity.HardenProgramData`, `EnsureDirectory`/`EnsureFile`, `PipeSecurityFactory` | **Implemented & unit-tested** — `ServiceInstaller.Install` copies `Axiom.Service.exe` out of `%LOCALAPPDATA%` into `MachineStateSecurity.ServiceImagePath` (`Program Files` with `usersMayRead: false` Admin/SYSTEM-only ACL), verifies SHA-256 (`FilesMatch`), hardens `ProgramData` ACLs (`HardenProgramData`), registers the quoted `binPath=`, and restricts named-pipe clients to the persisted `AllowedSid` via `PipeSecurityFactory`. | Verify upgrade over an existing `AxiomService` installation in a clean Windows 10/11 VM (`sc.exe qc AxiomService`, `icacls` check on `Program Files` binary & `ProgramData\Axiom`). |
| **Third-Party Vendor Installers** | `OptionalModuleInstaller.cs`: Blackbox installer SHA-256 pinned (`261122F5E879596E88D63C30D5D36D12B4E155986F83AA3EB83ADEB406E41179`), DKG pinned to `@origintrail-official/dkg@10.1.0` via embedded `package.json` + `package-lock.json` (`npm ci --ignore-scripts`), `autoUpdate.enabled = false` | **Verified & improved (`#305`, `#308`, `#309`, `#310`)** | Rejects hash mismatch before execution; captures `UserStateProtection` snapshots around both vendor installers and agent hooks so out-of-scope edits halt and roll back. |
| **Interrupted Upgrade Recovery** | `UpgradeDataGuard.Capture` + `VerifyAndRestore` | **Implemented & unit-tested (`UpgradeDataGuardTests.cs`)** | Keeps 3 timestamped backups of Blackbox data, Hermes config, Axiom JSON/DB logs, and DKG homes; restores missing or 0-byte files post-upgrade. |

---

## 2. Clean Windows VM Acceptance Checklist (Required Before `1.0`)
1. Download release assets to a fresh Windows 10/11 VM (no `.NET SDK`, no VC++ redistributable preinstalled, no `py.exe` launcher, standard user account + UAC admin prompt).
2. Verify `certutil -hashfile Axiom-Setup.exe SHA256` against `SHA256SUMS.txt`.
3. Install **Partial** mode -> verify firewall/DNS/autostart remain off and no third-party modules download.
4. Upgrade in-place to **Complete** mode -> verify UAC prompt count (`1`), service start, VC++ missing fallback (`oxigraph-worker`), `pwsh`/PS behavior, `UpgradeDataGuard` backup preservation, and clean uninstall/reinstall recovery.
