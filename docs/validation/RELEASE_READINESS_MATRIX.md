# Axiom 1.0 — Baseline Release Readiness Matrix (v0.32.0 Audit)

**Repository:** `a-51-50/Axiom`  
**Audited Baseline:** `v0.32.0` (`c9429be`, 2026-11-15)  
**Primary Target:** Windows desktop/service production readiness (with separate Linux/macOS gates)  
**Principle:** Detection is not enforcement. A requested block is not a verified block. A passing unit test is not independent runtime proof.

---

## 1. Reproduced Baseline Verification (`v0.32.0`)

Reproduced directly on `main` at `c9429be` before adding CI/validation deliverables:

| Check | Command | Observed Result | Scope & Evidence Limits |
|---|---|---|---|
| **Solution Release build** | `dotnet build Axiom.sln -c Release` | **Passed:** 0 warnings, 0 errors across all 21 projects (`TreatWarningsAsErrors=true`, `EnforceCodeStyleInBuild=true`) | Compiles & runs Roslyn analyzers; one publish-only `ILLink.targets` warning appears during `publish-setup.ps1` due to CPM `Microsoft.NET.ILLink.Tasks` pin (`NU1009`) |
| **Automated .NET test suite** | `dotnet test Axiom.sln -c Release --no-build -m:1` | **Passed:** **966/966** passed, 0 failed, 0 skipped across 9 test assemblies | `Contracts` 152, `Core` 151, `Infrastructure.Windows` 81, `Persistence` 21, `Service` 94, `UI` 175, `McpServer` 33, `Presentation` 207, `UI.Avalonia` 52; mostly unit/in-process/mocked or read-only COM checks |
| **Package vulnerability audit** | `dotnet list Axiom.sln package --vulnerable --include-transitive` | **Passed:** 0 vulnerable packages across all 21 projects | Checked against `api.nuget.org` |
| **Locked-mode restore** | `dotnet restore Axiom.sln --locked-mode` | **Failed (`NU1004`):** 7 `src/` projects fail when restoring without explicit `-r win-x64` (`Contracts`, `Core`, `Persistence`, `Presentation`, `Infrastructure.Windows`, `Desktop.Avalonia.Windows`, `Service`) | Tracked in `#280`: shared lockfiles pin `win-x64` RIDs and stale internal ProjectReference `[0.12.0, )` / `[0.17.0, )` versions |
| **Release packaging (`v0.32.0`)** | `.\scripts\build-release.ps1` | **Passed:** `Axiom-0.32.0-win-x64.zip` (`82,037,827` bytes / 78.24 MB), `Axiom-Setup.exe` (`95,392,648` bytes / 90.97 MB), `SHA256SUMS.txt` uploaded to GitHub Release `v0.32.0` | Unsigned binaries (`#119`, `#289`); `--silent` guard without `--accept-risk` verified exit code `2` on `0.31.0`; live interactive Setup install not yet run in clean Windows VM |

---

## 2. Capability & Enforcement Readiness Matrix

Legend:
- **HOST / VM VERIFIED:** Observed end-to-end against real host/OS state cleanly (still requires re-validation in clean VM for 1.0 sign-off if tested on an older baseline).
- **UNIT / HEADLESS TESTED:** Verified via automated `.NET` unit, SQLite, headless Avalonia, or mocked-adapter tests; OS boundary or external daemon behavior is not yet proven live in VM.
- **DEGRADED / GAP:** Known defect, partial coverage, or honest fallback limitation tracked in open issues.
- **PROTOTYPE / UNWIRED:** Exists in library/research code or open PRs, not active as an OS security boundary.
- **UNSUPPORTED / BLOCKED:** Cannot be relied on as an enforcement boundary in the current Windows user-session architecture or missing OS backend.

| Area | Codebase Implementation | Current Verification Status | Honest Boundary & Remaining Validation Required (Phases 3–9) |
|---|---|---|---|
| **Live traffic & flow history** | `IpHelperConnectionSource`, `MonitoringWorker`, `HistoryWriter`, SQLite persistence (`Axiom.Persistence`) | **Unit Tested + Host Observed** (service + DB migration/retention/corrupt-recovery tests pass) | Re-verify cold-start service install + live traffic capture & 5m live counter chart accuracy on clean Windows VM. |
| **Windows Firewall rules (Agent/App scope)** | `WindowsFirewallPolicyAdapter`, `StaComExecutor`, `FirewallRuleCoordinator`, `AgentFirewallEnforcer`, `OwnedRuleMatcher`, `ProtectionWriteConsent` | **Read-only COM Verified + Unit Tested (Fake Adapter)** (`Axiom.Core.Tests`, `Axiom.Service.Tests`, `Axiom.Infrastructure.Windows.Tests`) | **Phase 4 gap:** Two-var write gate prevents accidental writes in unit tests; live `OS_DENY_VERIFIED` dual-destination canary, IPv4/IPv6 block, process restart, exe replacement, and clean rule removal must be proven in an isolated Windows VM. |
| **Privacy Shield (DNS filtering & DoH)** | `PrivacyShieldController`, `DnsProxyServer`, `PrivacyDnsFailSafe`, `PrivacyShieldSourceUpdater`, `WindowsDnsRecoveryAdapter` | **Unit / Service Tested** (`Service.Tests` + category/normalization tests) | **Phase 4/5 gap:** Live adapter DNS switch, blocked-domain `NXDOMAIN` behavior, upstream DoH under offline/firewall interference, and fail-safe adapter restore on unexpected service crash must be tested in clean Windows VM. |
| **Agent protection hooks (11 host families)** | `OpenCode`, `Codex`, `Claude`, `Cursor`, `Copilot`, `Gemini`, `Windsurf`, `Cline`, `ZCode`, `DeepSeek`, `Hermes` protection helpers in `Axiom.Presentation` + `SecurityPageViewModel` | **Unit / Provisioning Tested + Partial Host Probe** (`Axiom.UI.Tests`, `OFFLINE_CONTINUITY_AUDIT.md`) | **Phase 3 gap:** Cooperative hooks (`HOST_DENY_SENT` / `HOST_DENY_VERIFIED (CANARY)`). Guard runs under same user token (`TrustedFileBroker` / `WindowsRunnerAndBrokerProbe` in `E3` are feasibility/prototype only). `#275` (unquoted Antigravity hook path with spaces) open; bypass matrix across shells, encodings, symlinks, child processes needed in VM. |
| **Blackbox / DKG offline continuity** | `BlackboxLocalState.EvaluateContinuity`, `DkgContextAnnotator`, `DkgHomeResolver`, `DkgIdentityProbe`, `AgentsPageViewModel` | **Unit Tested + Isolated Probe** (`Axiom.Presentation.Tests`, `OFFLINE_CONTINUITY_AUDIT.md`) | **Phase 5 gaps:** Guard continues offline for small compiled rulesets (`ruleset.json`) without port `9700`; upstream `DKG-lookup B6` (`1.1M` dependency/IOC rules) fails open when store is down unless `verified_lookup_fallback: "index"`, and upstream `bip39_english.txt` CRLF issue can disable seed-phrase detection on Windows (`OFFLINE_CONTINUITY_AUDIT.md`). Need live VM offline reboot & reconnect tests. |
| **Threat sharing & reporter safety** | `ThreatShareController`, `ThreatShareStore`, `ThreatShareEvidenceClass`, `UpgradeDataGuard` | **Unit Tested** (`Contracts`, `Service`, `Presentation`) | **Phase 6 validation:** Verify end-to-end with isolated synthetic key that zero private paths/prompts/canaries/AI hypotheses leave automatically and `UpgradeDataGuard` preserves keys across real installer upgrades. |
| **Local file scan, Community feed & VirusTotal** | `FileScanner`, `CommunityFeedClient`, `VirusTotalClient`, `SecurityPageViewModel` (`v0.32.0` `VT Check` + local feed notice) | **Unit + Headless Tested** (`Contracts.Tests`, `SecurityFileScanTests` 52/52 Avalonia tests pass) | `CommunityFeedClient` intentionally caps parsed entries at `1000` hashes; manual E2E spot-check in running desktop recommended. |
| **Local IPC & Read-only MCP Server** | `PipeServer`, `PipeSecurityFactory`, `PipeClientIdentity`, `Axiom.McpServer` | **Unit Tested** (DACL, caller SID check, 4 MiB framing, 33/33 `McpServer.Tests`) | Verify same-machine cross-user isolation and real MCP stdio client attach without privilege escalation. |
| **Windows Installer (`Axiom-Setup.exe`) & Modules** | `Axiom.Setup` (`SetupNativeWindow.cs`, `SetupInstaller.cs`, `app.manifest`), `UpgradeDataGuard`, `OptionalModuleInstaller` | **Built & CLI Gate Checked** (`v0.31.0`/`v0.32.0`, 90.97 MB Win32 single-file) | **Blockers:** Unsigned EXE (`#119`, `#289`); installer prerequisites (`#305` `py` launcher, `#308` VC++ runtime fallback, `#309` PS 7 vs PS 5.1 arg mangling, `#310` non-interactive `dkg init`, `#315` upstream runtime defects) still open; clean VM Win32 install/upgrade test pending. |
| **Desktop UI (Avalonia)** | `Axiom.UI.Avalonia`, `Axiom.Desktop.Avalonia.Windows` | **Headless Tested (`52/52`)** (navigation, row click stability in `0.31.0`, `VT Check` clarity in `0.32.0`) | Open UI bugs: `#284` (Agent Protection endless loading state when Blackbox offline), `#285` & `#286` (clipping/overflow at `1024x768`), `#300` (`Contact` + update indicator). Note legacy WPF `Axiom.Desktop`/`Axiom.UI` still compiled in `Axiom.sln` (175 `UI.Tests`). |
| **Linux & macOS Ports** | Branches in PR `#274` (macOS), PR `#276` (Linux), PR `#325` (IPC dispatcher split) | **Experimental / Separate PRs** (`macos-port.yml` manual workflow exists) | Not merged into `main`. Open bugs `#175`, `#280`, `#281`, `#290`. Keep gated separately so Windows 1.0 verification stays focused while keeping core portable. |

---

## 3. Open PR Reconciliation (`main` at `v0.32.0`)

| PR | Title | Overlap / Readiness Notes |
|---|---|---|
| **#325** | `refactor(ipc): portable IPC dispatcher, per-command access classes, write gate in Core (macOS split S1a)` | Small focused split from cross-platform work; review cleanly against `Axiom.Core` / `Service`. |
| **#304** | `feat(ui): add a Contact button next to Donate (#300)` | UI enhancement; reconcile with latest `SupportView` / header layout (`#285`). |
| **#303** | `fix(ui): select the row a pointer press lands on (#296)` | **Likely superseded by `v0.31.0` (`5a5c149`)** which fixed row selection + `SharedSelectedItem` + `CollectionSync` across all tabs; inspect diff and close or rebase if anything remains. |
| **#302** | `feat(agents): offline enforcement decision bridge (controller + IPC + adapter)` | Enforcement `E2b` wiring; evaluate carefully under Windows CI & Phase 3/4 tests. |
| **#301** | `docs(agents): current host-deny audit and capability matrix` | Audit docs for `E2`; align with this validation baseline so docs don't contradict `v0.32.0`. |
| **#276** | `Linux port: systemd daemon, nftables + eBPF enforcement, Avalonia host (#150)` | Large platform PR; keep on Linux validation track (Phase 8). |
| **#274** | `macOS port: Avalonia app, launchd daemon, Network Extension filter` | Large platform PR; keep on macOS validation track (Phase 8). |

---

## 4. Initial Release Triage (`v0.32.0` -> `1.0` Road)

### Release Blockers (Must fix or prove before `1.0`)
1. **No automated Windows CI (`#273`, `#289`)** — *Addressed in Phase 2 via `.github/workflows/windows-ci.yml`; verify green run on GitHub.*
2. **Unsigned Windows installer / Portable EXEs (`#119`, `#289`)** — Need Authenticode signing strategy (e.g., SignPath Foundation evaluation) + documented SmartScreen / SHA-256 verification.
3. **Full-install reliability defects (`#305`, `#308`, `#309`, `#310`, `#315`)** — PowerShell 5.1 argument mangling, interactive `dkg init` hang, missing `py` launcher, VC++ runtime fallback, and vendor Blackbox defects.
4. **Live OS Enforcement & Offline Continuity proof in isolated VM (Phases 3, 4, 5)** — Real WFP `OS_DENY_VERIFIED` dual-destination block & rollback, IPv6/exe replacement, Privacy Shield DNS crash failsafe, offline reboot + clean Win32 `Axiom-Setup.exe` install/upgrade verification.
5. **Hook quoting & misleading UI states (`#275`, `#284`, `#285`, `#286`)** — Unquoted Antigravity hook path with spaces (`#275`), infinite loading preview when Blackbox unavailable (`#284`), layout clipping at `1024x768` (`#285`, `#286`).

### Acceptable Limitations (Document clearly for `1.0`)
1. **Same-user hook boundary (no kernel driver / no Windows ACL rewrite):** Agent filesystem protection operates at the hook layer (`HOST_DENY_VERIFIED (CANARY)`) under the signed-in user token, not OS-enforced file sandboxing (`E3` AppContainer/broker remains feasibility stage).
2. **Blackbox `1.1M` dependency/IOC tier offline behavior:** Requires `verified_lookup_fallback: "index"` or active local Oxigraph (`127.0.0.1:7879`); default fails open when store is stopped (`OFFLINE_CONTINUITY_AUDIT.md`).
3. **DNS fallback prioritizes connectivity:** Stopping Privacy Shield restores adapter DNS rather than stranding the machine offline (`PRIVACY_SHIELD.md`).
4. **Legacy WPF `Axiom.Desktop` vs Avalonia `Axiom.Desktop.Avalonia.Windows`:** Releases ship Avalonia UI; legacy WPF remains in solution for existing tests until retired.

### Follow-Up (Post-1.0 or parallel tracks)
1. **NU1004 locked-mode lockfile split (`#280`)** — Decouple RID-specific `win-x64` restore lockfiles from portable projects so `--locked-mode` works identically on Windows/macOS/Linux.
2. **PR `#303` triage & `ENFORCEMENT.md` E1-only header refresh (Phase 9)** — Reconcile stale `0.10.23` / `0.23.0` / `E1-only` prose in docs against `0.32.0` (`E1/E2/E4/E5` status).
3. **Cross-platform macOS (`#274`) & Linux (`#276`, `#175`, `#290`) validation gates (Phase 8).**
