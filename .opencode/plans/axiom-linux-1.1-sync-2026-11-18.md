# Axiom Linux 1.1.0 Windows-parity sync — 2026-11-18

Status: **implemented, tested, packaged and VM-verified on branch `recon/linux-main-1.1.0`**
(base `07d2daf707eb016ef188ef61221786ed2c1c96ef` = `upstream/feature/linux-recon-0.97.0`,
which already merges pinned v1.1.0 `da1987a1896275f0127eb8fe176c1a780471ebe9` and the DCO
attestation). Windows runtime is out of scope; this is the Linux host.

## Scope (smallest root-cause changes)

1. **Privacy Shield stale "active" when the daemon is unreachable**
   - `PrivacyShieldPageViewModel`: a failed read/write (`ServiceUnavailableException`) now marks the
     state *unknown* (`IsResolverActive = false`, new `IsServiceUnavailable`) and raises property
     changes; a successful answer clears it and notifies on the transition.
   - `SimpleHomePageViewModel`: `IsFullyProtected`, `PrivacyStatusText`, `PrivacyActionText`
     ("Retry"), `HeroBadgeText/Headline/Summary` follow the known state, never the saved toggle
     alone; the retry re-reads instead of sending a guessed enable/disable.
   - `MiniHomePageViewModel`: `PrivacyButtonText` is `Privacy: unknown`; its toggle re-reads.
   - `ShellViewModel` header already reads `IsResolverActive`, which is now false while unknown.
   - Tests: `tests/Axiom.UI.Avalonia.Tests/PrivacyShieldAvailabilityTests.cs`.
2. **Optional module install wording on Linux**
   - `OptionalModuleInstaller.UnsupportedInstallMessage` is computed from `PlatformText.OsName`
     (Linux renders "Linux", macOS "macOS"). `IsInstallSupported` stays Windows-only.
   - Test: `Axiom.Presentation.Tests/OptionalModuleInstallerTests.Unsupported_install_message_names_the_running_os`.
3. **Trader Shield unavailable visibility**
   - `SecurityView.axaml` keeps `TraderShieldSectionView` visible and binds `IsEnabled` to
     `IsAvailable`, so `UnsupportedPlatformText` is readable without enabled toggles.
   - Test: `TraderShieldSectionViewModelTests.Trader_shield_stays_visible_but_disabled_when_the_platform_cannot_run_it`.
4. **Linux DNS partial restore**
   - `LinuxDnsConfigurator.RestoreIfNeeded` records `LastRestoreError` naming the links that failed
     while keeping the backup (retried on next start); `LinuxPrivacyDnsPlatform` exposes it and
     logs it to the journal. `IPrivacyDnsPlatform` is unchanged, so Windows/macOS contracts hold.
   - Tests: partial rollback + snapshot retention, and DoH upstream discovery/fallback in
     `tests/Axiom.Infrastructure.Linux.Tests/DnsBackendTests.cs`.
5. **Parity check** — Mini daemon-down "Shield: unknown"/"Unknown", Guard "Not protected",
   Expand, fractional-DPI fitting, FirstRunDialog, Settings theme/autostart, rule export/import,
   Trader Shield and the Linux install wording were exercised live; no further code bug found.

Reviewed safety guarantees (BPF hand-over, pins, maintainer scripts, package identity, unit
restart policy, `SO_PEERCRED`) were preserved; no Windows/macOS code or IPC access tests changed.

## Gates (see evidence)

- `Axiom.Portable.slnx` Release build 0 warnings / 0 errors; 1,366 tests green.
- `Axiom.Desktop.Avalonia.Linux.Tests` 51; `Axiom.Infrastructure.Linux.Nft.Tests` 203.
- Windows-targeted cross-build (`EnableWindowsTargeting`, Service windows TFM and
  `Desktop.Avalonia.Windows`) 0/0. `Axiom.Desktop` (WPF) and `Axiom.Setup` remain unbuildable on
  Linux (NU1102/NU1004), as on `main`.
- DEB `1.1.0+linux.1`, lintian 0 errors / 0 warnings, no `.exe/.msi/.ps1`.
- Ubuntu 24.04.5 VM: empty prestate → 0.73.0+linux.7 → in-place 1.1.0 upgrade (rule, theme and
  settings preserved, doctor 13 PASS), 4 BPF programs/hand-over, canary 0 slips, second-user IPC
  denial, live Privacy Shield + DoH + fail-closed DoH failure + DNS restore, GUI in Xvfb across
  Mini/Simple/Advanced, clean purge with no residual nft/BPF/unit/data.

## Known non-Windows/deferred gaps

RPM/Fedora packaging, arm64 artifact, native Wayland, code signing, and native Linux hooks for
Blackbox/DKG (AI Agent Guard stays "Not verified" on Linux; no guided installer on Linux).
