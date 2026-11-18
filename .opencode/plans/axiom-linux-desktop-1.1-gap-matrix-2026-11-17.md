# Axiom Linux desktop 1.1 — functional gap matrix (read-only comparison)

Date: 2026-11-18 (UTC). Author: build agent (single builder). This is analysis, not a merge or
release claim. Status legend: **Same** = shared code used unchanged; **Ported** = platform
implementation exists in the Linux reference; **Gated** = present but honestly unavailable on
Linux; **Missing** = no Linux implementation; **Unverified** = code exists, native behaviour not
measured for this snapshot.

## 1. Authority and baselines

- Maintainer handoff: issue **#441**, body "v1.1.0 execution plan", plus the owner comment of
  2026-11-17T22:06:53Z
  (`https://github.com/a-51-50/Axiom/issues/441#issuecomment-6962366890`). It moves port
  leadership to @dreddster, keeps @brxtrac on Linux extraction/CI/provenance, and does not
  forbid read-only analysis. This matrix is analysis requested by the operator; it assigns no
  merge and edits no privileged code.
- Desktop target snapshot: `da1987a1896275f0127eb8fe176c1a780471ebe9` (**v1.1.0**, PR #440),
  worktree `/tmp/opencode/axiom-integration-1.1-20261117/wt-1.1`.
- Linux reference snapshot: `07d2daf707eb016ef188ef61221786ed2c1c96ef`
  (`feature/linux-recon-0.97.0`, based on `da1987a`), worktree `.../wt-linux-src`.
- Upstream `main` is `26f1047acb63e40cb9073130dde943b3b10e0adf` (v1.3.0). **Not** used as the
  desktop baseline here; it contains later module releases the owner asked not to chase.
- Method: file and symbol comparison between the two snapshots, plus test execution at the Linux
  snapshot. Feature lists in issues were not treated as evidence.
- S1a/S1b merge state does not block this comparison; it does block the code rows that need them.

## 2. Measured test state (Ubuntu 24.04.5 host, SDK 10.0.403, 2026-11-18 02:3x–03:1xZ)

| Suite | Result |
|---|---|
| `Axiom.Portable.slnx` (11 test assemblies) | 1361 passed / 0 failed / 0 skipped |
| `tests/Axiom.Desktop.Avalonia.Linux.Tests` (not in the portable solution) | **51 passed / 0 failed** |
| `tests/Axiom.Infrastructure.Linux.Nft.Tests` (not in the portable solution) | **203 passed / 0 failed** |

The two Linux-only suites are **not** built by `Axiom.Portable.slnx`; they exist only in
`Axiom.sln`, which cannot build on Linux because of its Windows projects. That is a coverage gap
in the Linux CI gate (see F4). Total Linux-relevant tests available today: 1615.

## 3. Functional matrix

| # | Area | 1.1.0 target behaviour + source symbol | Linux reference actual + source | State | Minimal fix, callers and tests | Native proof | Next owner / dependency |
|---|---|---|---|---|---|---|---|
| 1 | Shell modes | `UiMode { Mini, Simple, Advanced }` + Glass palette: `src/Axiom.Presentation/SettingsContracts.cs:26`, `src/Axiom.UI.Avalonia/AxiomThemeVariants.cs:18`, `ShellViewModel.IsMiniMode` | Same shared views; Linux host instantiates the shared shell: `src/Axiom.Desktop.Avalonia.Linux/App.axaml.cs:95,113` | Same | None found. Keep UI tests (`Axiom.UI.Avalonia.Tests`) as regression gate | Carried: 16 Xvfb screenshots incl. light theme, `docs/LINUX_TEST_REPORT.md` row 2 | L6 owner; no dependency |
| 2 | Window size / DPI | Mini vs full layout and pixel-accurate working-area fit: `MainWindow.axaml.cs` constants `MiniWindowMinWidth=760`, `FullWindowMinWidth=900`; 1.1 has no `FitToWorkingArea` | 98 added lines in `MainWindow.axaml.cs` (`FitToWorkingArea`, cap in pixels then DIPs, fractional-scale overshoot note); Linux uses X11/GL or software rendering (`Program.cs`) | Ported | Add a headless layout test at scale 1.25/1.5 for the fit maths (pure calculation; no new UI). Caller: `MainWindow.OnOpened`, `ApplyWindowLayoutForMode` | Unverified: only 1600×1000 Xvfb evidence; no fractional-DPI run for this snapshot | L6; independent of S1a/S1b |
| 3 | Tray + close | Windows tray/close behaviour: `src/Axiom.Desktop/TrayStatusController.cs`, `src/Axiom.Presentation/TraySettingsStore.cs` | `StatusNotifierProbe.cs` (needs `org.kde.StatusNotifierWatcher`, `AXIOM_TRAY` override), `App.axaml.cs:302` tray creation; no watcher → close quits, never hides to a missing tray | Ported | None required. Unit tests exist (`LinuxHostTests.Tray_only_with_a_watcher_unless_overridden`, `Close_hides_only_with_a_tray`) | Carried: packaged launch P-4, watcher present, close-to-tray, `packaged-launch.png` | L6 |
| 4 | Autostart | Windows startup entry via `NotificationAndWindowSettings.cs` / `TraySettingsStore`; no `AutostartService` file at 1.1 | `LinuxAutostartService.cs` XDG entry `~/.config/autostart/com.axiom.firewall.desktop`, `--autostart`, stale-path detection and repair | Ported | None required; covered by 4 `LinuxHostTests` cases | Unverified natively for this snapshot (unit-tested only) | L6 |
| 5 | Theme + settings persistence | `ThemeSettingsStore` under LocalApplicationData; `UiMode` persisted | Linux follows `org.freedesktop.portal.Settings` colour scheme until a saved theme exists (`LinuxThemeService.cs`, `ThemeSettingsStore.HasSavedTheme`); paths through `src/Axiom.Contracts/AxiomPaths.cs` | Ported | None found. `MacDnsNote` naming reused for Linux in `PrivacyShieldPageViewModel` is cosmetic only | Carried: screenshots dark + light | L6 |
| 6 | Notifications | In-window always-on-top alert card `AxiomAlertService.cs`; background-window opt-out is Windows-only (`NotificationAndWindowSettings.cs:164,184`) | Same card service; **no libnotify/portal notification backend** on Linux | Same (card) / Missing (OS notifications) | Do not add a native backend before it can be tested; ensure Settings copy does not promise OS notifications on Linux. Tests: `NotificationSettingsStore` tests | Unverified | L6; needs product decision, not guessed |
| 7 | Privacy dashboard | 1.1 `PrivacyOverviewView.axaml`, `PrivacyOverviewPageViewModel`, wired at `ShellViewModel.cs:85` | Same shared page; Linux-specific wording via `PlatformText.DaemonSwitchesDns` (`PrivacyShieldPageViewModel.ManualSetupText`) | Same | None found. Add a Linux VM check that the dashboard shows resolver running/stopped and daemon-down states separately | Carried: privacy-shield and package screenshots | L6 / L5 |
| 8 | DNS consent, snapshot, rollback, DoH | 1.1 `PrivacyShieldController` adapter-DNS helper with the confirmation dialogs in `PrivacyShieldPageViewModel`; no `IPrivacyDnsPlatform` seam | `src/Axiom.Service.Hosting/Dns/IPrivacyDnsPlatform.cs`, `DnsProxyServer.cs`, `UpstreamRediscovery.cs` (added by the port); Linux: `LinuxDnsBackends.cs` (systemd-resolved / NetworkManager / resolv.conf), `LinuxDnsConfigurator.Redirect/RestoreIfNeeded`, `LinuxDnsRecoveryAdapter.cs`, `LinuxPrivacyDnsPlatform.cs` | Ported | Verify partial-rollback and DoH-failure paths surface the adapter error, and that the snapshot is retained; callers `PrivacyShieldController.OnResolverStarted`, `NetworkRecoveryCommand`. Tests: `DnsBackendTests`, `UpstreamRediscoveryTests`, `Axiom.Service.Hosting.Tests/DnsProxyTests` | Carried: VM P-8 shows `resolvectl`/`resolv.conf` unchanged after install; unit redirect/restore round trips | L5; S1b DNS seam still unmerged |
| 9 | Capabilities / offline truth | 1.1 `FirewallCapabilityReport` (status/reason, no `FilterEnforcement`, no `ConnectTimeLayer`), `ShellViewModel` status without an `UNKNOWN` branch | Adds `FilterEnforcementSummary.cs` (verified only on acked generation), `ConnectTimeLayerReport`, `Limitations`, `ShieldProtection`, `OverviewProtectionState`; `ShellViewModel.cs:883` `"UNKNOWN"` when the service does not answer; Linux adapter fills capabilities including external-modification and BPF-map limitations (`NftFirewallPolicyAdapter.GetCapabilitiesAsync`) | Ported | None found for truthfulness; add a Linux UI test for daemon-down → `UNKNOWN` (existing `DaemonStoppedStaleStateTests` covers the VM) | Carried: `docs/LINUX_TEST_REPORT.md:755` (daemon stopped → Simple shows unknown) | L6 |
| 10 | Firewall rule flow / read-back / receipts | 1.1 `RuleApplyResult` (`Success` = adapter read-back, not a packet proof), `RuleVerify`, `FirewallPageViewModel` apply/remove, Windows adapter | Nft path: `NftFirewallPolicyAdapter.VerifyAsync/GetCapabilitiesAsync`, `NftTable.ParseGeneration`, integrity check for externally removed owned rules, `OwnedRulesMissing`; UI shows rejected rules and pending generations (`FilterEnforcementSummary`), per-rule `ConnectTimeBlockingProven`/`CoverageReason`. Firewall change receipts are the audit journal; `enforcement.receipts` is **agent** enforcement, not firewall | Ported | None in code found. Prove `rule.apply` → real deny → `rule.remove` → allow on the packaged DEB again for this snapshot (VM), since docs evidence predates it | Carried: VM P-5 (curl rc=7 after apply, 200 after remove), P-8 reinstall keeps `managedRuleCount:0` | L3; S1a for IPC shape |
| 11 | BPF connect-time / handover | Not present in 1.1 (Windows uses WFP/firewall only) | `BpfEngine.cs` (`Handover` record, `RollBackNewSet`, pending/stale/neutralised status), `BpfVerdictPlanner`, `BpfKernelKeyCheck`, `BpfCapabilityProbe`, `BpfPinCleanupTests`, `BpfHandoverTests` (203 nft/BPF tests) | Ported | Re-run restart/SIGKILL handover and rapid-connect canaries on this snapshot; older `0/1779` and `0/1883` results are not evidence for it. Unowned pin cleanup test exists; add map-deletion failure case if missing | Carried from earlier branch only; **not verified for this snapshot** | L4; needs qualified non-author reviewer |
| 12 | AI guard / Blackbox install | 1.1 guided installers are PowerShell/Windows installer, no platform gate; `ProtectionProvisioner.ProvisionAtStartup` writes Windows agent configs | `OptionalModuleInstaller.IsInstallSupported => OperatingSystem.IsWindows()` and UI stops at the message; **message says "not available on macOS yet" on Linux** (`OptionalModuleInstaller.cs:70`); `ProtectionProvisioner.cs:140` returns null off Windows, so no Linux policy provisioning | Gated (honest) / **wording bug** | Fix the message to platform-correct text (caller `SecurityPageViewModel.cs:853,914`, tests `OptionalModuleInstaller`-related). Do not enable install on Linux without real Blackbox support | None, correctly: no Linux AI guard claimed | L6 label fix (small, non-privileged); full guard is a separate work item |
| 13 | Trader Shield | 1.1 `TraderShieldSectionViewModel.IsAvailable => !DistributionContext.IsStorePackage` (would appear on Linux) | Reference adds `_platformSupported` (`configPath` requires Windows or a test path) + `UnsupportedPlatformText`; view hidden via `IsVisible="{Binding IsAvailable}"` (`SecurityView.axaml:192`); the read-only path is never `~/.hermes/config.yaml` | Gated | None required; keep the 1.1 default-path hazard out. Add a test asserting `IsAvailable == false` on non-Windows without an explicit path | Unit-testable; no VM needed | L6; ahead of any Trader Shield Linux work |
| 14 | Full policy provisioning / agent enforcement | 1.1 `ProtectionProvisioner` (complete profile) and `EnforcementPolicyProvisioner.EnsureDefault` write Windows agent configs | Non-Windows startup provisioning returns null; Blackbox mode store hidden when its venv is absent (`BlackboxModeStore.IsAvailable => File.Exists(AgentPlatform.VenvPython(...))`); **unverified** whether `ServicePlatform.ConfigureAgentEnforcement` is bound on Linux (`Program.cs:54`, Windows and Unix partials only) | Gated / Unverified | Verify Linux binds no agent-enforcement service, or that `enforcement.*` stays unavailable without a guard; if it binds, label it unsupported and deny provisioning. Tests: `IpcCommandAccessTests`, `EnforcementWiringTests` | None | L2/L4 decision; security-sensitive, needs owner + reviewer |
| 15 | Service / packaging launch | 1.1 Windows service + installer; Linux has no unit at 1.1 | systemd unit `Type=notify`, `Restart=on-failure`, `RestartSec=2`, `ProtectSystem=strict`, cgroup/BPF paths writable (`SystemdUnit.cs:73-121`); `axiom-firewall` DEB with `/usr/lib/axiom-firewall`, launcher, polkit action; `axiomd --install-service` | Ported | Uninstall/purge and upgrade 0.53/0.64/0.97→1.1 are not evidenced in `docs/LINUX_TEST_REPORT.md` (row 352 says not done); the current DEB smoke builds 1.1.0+ci but does not install | Carried: P-4/P-8 install and reinstall on VM; no purge evidence | L7; separate release gate |

## 4. Findings that are bugs or misrepresentation risks (not fixed here)

- **F1 (security gate, known):** `src/Axiom.Service.Hosting/Ipc/IpcCommandAccess.cs:31` still has
  `bool CanReadPrivate = true` as an implicit default in the Linux reference — exactly the #325
  gate. The Linux transport builds the caller from kernel peer credentials
  (`UnixSocketIpcTransport` → `PeerAuthorization.Decide` → `IpcCaller`), so an under-specified
  call site would grant private reads silently. Fix belongs to S1a (both flags explicit), then the
  Linux transport must pass both. Tests: `IpcCallerPermissionTests`, `LinuxEnforcementIpcAuthorizationTests`.
- **F2 (wording):** on Linux, `OptionalModuleInstaller.UnsupportedInstallMessage` says "not
  available on macOS yet". Fix the text only; no behaviour change. Callers:
  `SecurityPageViewModel.cs:853,914`.
- **F3 (CI coverage):** `Axiom.Portable.slnx` omits `Axiom.Desktop.Avalonia.Linux.Tests` and
  `Axiom.Infrastructure.Linux.Nft.Tests`; the Linux CI gate (PR #443) therefore does not run 254
  passing Linux tests. Fix: add the two projects (and their sources) to the portable solution, or
  list them explicitly in the workflow; then update the workflow's expected counts.
- **F4 (unverified security surface):** whether Linux binds the agent-enforcement service
  (`ServicePlatform.ConfigureAgentEnforcement`) is not established by this read. If it does, a
  Linux client could see `enforcement.*` capabilities without any native guard behind them. This
  needs the L2 owner's confirmation before any claim either way.

## 5. What is *not* claimed

- No Windows runtime or Windows-parity claim; shared changes still require the existing Windows CI
  when PR'd.
- No Linux production, signing, AI-guard parity or "Complete" claim.
- Builds are not functionality: mode/DPI/tray rows rely on code + carried screenshots, not a fresh
  native run.
- nft read-back is not a packet proof; `RuleApplyResult.Success` is adapter read-back only.

## 6. Bounded next work (ordered, no overlap with S1a/S1b edits)

1. **CI coverage (owned, non-security, unblocked):** add the two omitted Linux test projects to
   `Axiom.Portable.slnx` (or the workflow test list), re-run locally (expect 1615 tests), update
   PR #443. Owner: @brxtrac. Billing block on hosted runs is separate and still open.
2. **L1 IPC (security-sensitive):** on the S1a merge result, make `CanReadPrivate` explicit in
   every `IpcCaller` construction, including `ServicePlatform.Linux` / `UnixSocketIpcTransport`;
   keep `uid:N`, 0700/0600 socket data and second-user denial tests green. Owner: @dreddster with
   @brxtrac coordination; reviewer required.
3. **L6 desktop evidence (unblocked):** fractional-DPI fit test, daemon-down `UNKNOWN` test on
   Linux, autostart/tray already covered; label notifications honestly. Owner: @dreddster.
4. **L5 DNS evidence (unblocked once S1b lands):** partial-rollback and DoH-failure VM run, keep
   snapshot on failure. Owner: @dreddster.
5. **AI guard labelling (small, unblocked):** fix F2 wording and state "agent protection not
   available on Linux" where install is offered. Owner: @brxtrac / @dreddster to confirm UI owner.
6. **L7 packaging (later):** uninstall/purge and 0.53/0.64/0.97→1.1 upgrade evidence; add to
   packaging matrix before any candidate claim.

## 7. Reproduction commands

```bash
export PATH=/root/.dotnet:$PATH
cd /tmp/opencode/axiom-integration-1.1-20261117/wt-linux-src   # 07d2daf7
dotnet restore Axiom.Portable.slnx --locked-mode
dotnet build Axiom.Portable.slnx -c Release --no-restore
dotnet test Axiom.Portable.slnx -c Release --no-build --no-restore -m:1
dotnet test tests/Axiom.Desktop.Avalonia.Linux.Tests/Axiom.Desktop.Avalonia.Linux.Tests.csproj -c Release
dotnet test tests/Axiom.Infrastructure.Linux.Nft.Tests/Axiom.Infrastructure.Linux.Nft.Tests.csproj -c Release
```

Counts from 2026-11-18: 1361 / 51 / 203, all passing, no skips.
