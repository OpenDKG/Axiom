# Axiom — Avalonia Migration Baseline

Status: baseline captured; first Avalonia shell and service boundary implemented
Branch: `feature/avalonia-windows-first`
Baseline commit: `61d5520` (`feat(agents): add opt-in incremental auto-sync`)
Date: 2026-11-07
Scope: Windows-first WPF → Avalonia UI migration. Linux/macOS firewall and monitoring backends are
out of scope for this stage.

## 1. Environment

| Item | Value |
|---|---|
| OS | Windows 10 IoT Enterprise LTSC 2021 |
| OS build | 10.0.19044 |
| .NET SDK | 10.0.403 (`global.json` rollForward `latestFeature`) |
| Screen | 1920 × 1080 |
| Desktop DPI | 96 (100%) |
| GPU | NVIDIA GeForce RTX 3060 |
| WPF rendering | software rendering by default (`App` sets `RenderMode.SoftwareOnly` unless `AXIOM_HARDWARE_RENDER=1`) |
| Repository | worktree at commit above; working tree clean before this document was added |

Windows 10 19044 is a supported smoke-test target in this baseline. The handoff correctly notes that
it should not be assumed equivalent to Windows 11 CI.

## 2. Build and test baseline

Commands were run from the migration worktree.

| Command | Result |
|---|---|
| `dotnet restore Axiom.sln --locked-mode` | **passed after normalizing the committed lock files** |
| `dotnet build Axiom.sln -c Release --no-restore` | **0 warnings, 0 errors** |
| `dotnet test Axiom.sln -c Release --no-build --no-restore` | **374/374 passed** |

The initial baseline exposed a pre-existing lock/RID mismatch: source projects carried `win-x64`
lock sections while test projects had none. The normalization removed those stale RID sections and
refreshed the project dependency version references. Locked restore is now reproducible with the
standard handoff command.

Test breakdown:

| Test project | Passed |
|---|---:|
| Axiom.Contracts.Tests | 55 |
| Axiom.Core.Tests | 66 |
| Axiom.Infrastructure.Windows.Tests | 40 |
| Axiom.McpServer.Tests | 33 |
| Axiom.Persistence.Tests | 14 |
| Axiom.Service.Tests | 16 |
| Axiom.UI.Tests | 140 |
| Axiom.Presentation.Tests | 6 |
| Axiom.UI.Avalonia.Tests | 4 |
| **Total** | **374** |

## 3. Screenshot baseline

Screenshots are retained locally under `artifacts/avalonia-baseline/` and are intentionally ignored
by Git (`artifacts/`). They contain local activity and must not be committed or shared without
sanitizing them.

| Set | Pages | Size |
|---|---:|---|
| `1460x900/` | 11 | reference window size |
| `1080x720/` | 11 | minimum supported window size |
| `service-mode/1460x900/` | 11 | existing Windows service + named-pipe mode |
| `service-mode/1080x720/` | 11 | minimum size in service mode |

Captured pages: Overview, Connections, Applications, Events, Agents, Firewall, Security, Privacy
Shield, AI Analyst, Support, Settings.

The service-mode set was captured by running `Axiom.Service.exe` and launching the worktree desktop
with `--service`. The in-process set was captured without that flag. The worktree desktop build does
not contain the installed bundled service payload, so the flag was required; the installed package
starts the bundled service automatically.

Not captured yet:

- 125%, 150% and 200% Windows scaling. The desktop is currently at 96 DPI and changing it requires a
  sign-out/sign-in cycle. These must be captured manually before visual parity is signed off.
- Hardware-rendering mode, RDP, GPU-reset and sleep/resume states.
- First-run, installer and all native dialogs at both window sizes.
- A controlled performance run and a 24-hour soak.

## 4. Shell and startup baseline

`MainWindow.xaml` is a frameless WPF window:

- Reference size 1460 × 900; minimum 1080 × 720.
- Custom `WindowChrome` title bar, 38 px caption height, drag/maximize/restore/close handlers.
- 236 px navigation rail; 64 px page header; 30 px status strip.
- Navigation order: Overview, Connections, Applications, Events, Agents, Firewall, Security,
  Privacy Shield, AI Analyst, Support, Settings.
- Agents is omitted from the Microsoft Store package.
- Header theme selector has Dark · Graphite, Dark · Midnight, Light · Clean and Light · Warm.
- Status strip combines monitoring, firewall, storage, data-source, mode, firewall-badge and IPC
  text.
- Single-instance mutex and a show-window event signal an existing instance.
- Tray icon, notifications, file dialogs, clipboard and external links are Windows-host behavior.
- `App` performs legacy data migration, agent-hook maintenance, first-run onboarding, theme
  application, bundled service startup and monitor composition.

`Axiom.Desktop` is `net10.0-windows`, `UseWPF` + `UseWindowsForms`, and currently the only executable
composition root. `Axiom.Setup` is WPF and embeds `Axiom.Desktop.exe`, `Axiom.Service.exe` and the
starter community feed. `scripts/publish-standalone.ps1` still publishes the WPF desktop.

## 5. Page inventory

| Page | View / ViewModel | Primary data and controls | Main commands | States that must survive |
|---|---|---|---|---|
| Overview | `OverviewView` / `OverviewViewModel` | Live KPIs, agent activity table, throughput chart, new-connection events | Copy activity/event/JSON, jump to now, load more, toggle new events | read-only, service, no service, empty activity, Blackbox unavailable, demo history |
| Connections | `LiveConnectionsView` / `LiveConnectionsViewModel` | Search, protocol filter, new/loopback toggles, group-by-app, virtualized socket rows | Reset filters | live/read-only/service, empty, filters, high socket counts, missing process path |
| Applications | `AppsView` / `AppsViewModel` | Grouped executables, socket counts, paths, context menu | Block inbound/outbound, end task, copy path | firewall writes disabled, service unavailable, owned-rule capability, confirmation |
| Events | `EventsView` / `EventsViewModel` | Persisted history, range/category/search, grouped rows, paging | Refresh, export CSV | loading, empty, no service, query error, export success/failure, retention |
| Agents | `AgentsView` / `AgentsViewModel` | DKG/Blackbox cards, harness status, activity, findings, hook evidence, sessions, verified graph, auto-sync | Configure, test protection, refresh, open dashboard, sync, auto-sync, install hooks, module actions, mode, uninstall | connected/hooked/trust required/audit only/degraded/offline, graph synced/syncing, missing DKG, no Blackbox |
| Firewall | `FirewallRulesView` / `FirewallRulesViewModel` | Owned rules, editor, defaults, capability and read-back status | Refresh, apply rule, browse, remove, save/reset defaults, recheck policy | service required, writes disabled, applying, read-back mismatch, empty, error |
| Security | `SecurityView` / `SecurityViewModel` | Module probes, file scan, reputation, community feed, protected agents | Refresh, scan, check hash, module actions, test/refresh feed, mode, uninstall | installed/missing/action required/verified/degraded, permission required, no network |
| Privacy Shield | `PrivacyShieldView` / `PrivacyShieldViewModel` | Resolver profile/categories/port/upstream, custom lists, source catalog, live stats/blocked history, adapter DNS | Apply, enable/disable, refresh, import, clear form/history, update sources, set/restore adapter DNS | service required, disabled, active, unavailable, source failure, resolver limit, UAC cancelled |
| AI Analyst | `AiAnalystView` / `AiAnalystViewModel` | Provider/model/key, redaction, analysis history, findings | Save settings, analyze current activity, clear history | disabled, missing key, loading, request error, redacted output, no data |
| Support | `SupportView` / `SupportViewModel` | Repository/issues links, donation destinations, crypto addresses | Open repository/issues, open donation page, copy address | no telemetry, external-link failure, copied state |
| Settings | `SettingsView` / `SettingsViewModel` | Four themes, tray notifications, startup/minimized, build/runtime, privacy | Theme commands, repair startup | autostart unavailable/stale, store package, saved theme |

### Native dialogs and windows

| Window | Purpose | Baseline requirement |
|---|---|---|
| `FirstRunWindow` | Optional DKG/Blackbox/community setup, terms and risk acknowledgement | Apply must remain gated by the acknowledgement; Skip must change nothing |
| `BlackboxSettingsWindow` | Blackbox mode, severity, protected paths, detection toggles, community sharing | Save must read back and verify; no silent mode change |
| `AgentHookInstallWindow` | Complete versus partial installation boundaries | Partial must not change agent files |
| `CommunitySetupWindow` | HTTPS community feed and optional token | Token handling must remain local/protected |
| `DkgLogWindow` | Bounded DKG log tail | Read-only, sanitized, no arbitrary file access |
| `DonationWindow` / `DonationView` | Donation destinations and copy actions | No payment processing inside Axiom |
| `ReputationSetupWindow` | VirusTotal hash-only lookup key | DPAPI storage, no file upload |

## 6. Observed baseline findings

1. **Minimum-width layout is clipped.** At 1080 × 720 the Overview KPI row and activity table extend
   past the right edge; Connections/Events tables also clip columns. A responsive layout is required,
   not just a resized screenshot.
2. **Service mode needs an explicit host path in an unpackaged worktree build.** The desktop stays
   in-process read-only unless `--service` is passed and `Axiom.Service.exe` is running; the installed
   package supplies the bundled service. The Avalonia host must preserve the installed-service
   behavior and clearly label disconnected/stale states.
3. **Screenshots contain local activity.** They are useful for parity review but are private and
   must remain out of Git.
4. **The workload is live.** Socket/activity counts and module status vary between captures; parity
   screenshots must record the timestamp and mode rather than compare raw numbers.

One uncontrolled memory sample in service mode was approximately 306 MB working set / 190 MB
private for the desktop and 595 MB working set for the service process. These are not a performance
baseline and must be remeasured with a fixed workload, resolution, mode and idle period.

### Avalonia slice sample (2026-11-07, 96 DPI, 1460×900, service mode)

After 35 seconds of idle live monitoring with the service running:

| Process | Working set | Private |
|---|---:|---:|
| Avalonia desktop | 177.2 MB | 127.9 MB |
| Axiom.Service | 315.4 MB | 370.0 MB |

This is a single uncontrolled sample, not a regression gate. Re-measure with a fixed workload,
resolution, mode and idle period before drawing conclusions.

## 7. Parity checklist for every migrated page

- [ ] Live data source, not mock data.
- [ ] Every command and binding from the WPF page is present.
- [ ] Empty, loading, offline, read-only, permission-required and degraded states match.
- [ ] Keyboard focus, tooltips, context menus and copy/export behavior match.
- [ ] Sorting, filtering, grouping, paging and scroll retention are preserved.
- [ ] Local persistence and privacy semantics are unchanged.
- [ ] 1460×900 and 1080×720 screenshots match the reference; 125/150/200% checked manually.
- [ ] Headless test covers primary navigation/state transitions.
- [ ] No new privileged, firewall-write, DNS, upload or hook path was introduced.

## 8. Exit condition for this step

Baseline is complete when the repository records:

- exact commit and SDK;
- build/test results and known pre-existing failures;
- screenshots for all pages in both modes at reference and minimum sizes;
- page/dialog command inventory;
- known layout and environment limitations.

The portability matrix is tracked separately in `docs/AVALONIA_PORTABILITY_MATRIX.md`.

## 9. Current Avalonia slice (2026-11-07)

Implemented in `Axiom.UI.Avalonia` with real data, real service calls and explicit offline states:

| Page | Data source | State covered |
|---|---|---|
| Overview | `ConnectionMonitor` + `TrafficEngine` | live, service mode, offline, measured throughput chart, 5m/1h/24h/7d/30d ranges |
| Connections | `ConnectionMonitor` | full socket columns, search, protocol/new/loopback filters, live, service mode, offline with last capture timestamp |
| Applications | `ConnectionMonitor` / `AppGrouping` | live inventory, read-only, service mode |
| Events | service `history.query` | live, empty, service required, service offline, CSV export |
| Firewall | service `rules.query` | available, read-only, service offline, apply/remove gated |
| Privacy Shield | service `privacy.status/configure` | active, disabled, service required, service offline, UAC-gated adapter DNS |
| AI Analyst | local monitor + configured provider | disabled, configured, manual/automatic, DPAPI-protected key |
| Security | local module probes + file scan + feed | module status, scan, hash lookup, community feed, agent hook install |
| Agents | Blackbox dashboard + local probes | health, verified sync, hook evidence, activity, findings, mode/settings |
| Support | bundled destinations | external links, clipboard, no configured destination |
| Settings | per-user stores + Windows host | four palettes (Dark, Light, Dark Midnight, Light Warm), startup, tray notification preference, build/runtime |

Host infrastructure implemented in `Axiom.Desktop.Avalonia.Windows`:

- bundled service startup and `--service` mode;
- service capabilities/health probe with explicit `service offline` text;
- single-instance mutex and show-window signal;
- tray icon with Open, notifications toggle and Exit;
- `--start-minimized` and `--autostart` preference handling;
- native confirm, save/open dialogs, clipboard and external links;
- Windows autostart registration, theme application, DPAPI key protection, UAC DNS helper.

All eleven parity pages are now listed in the Avalonia navigation. Native setup dialogs are
implemented in Avalonia: reputation provider, community feed, agent hook installation (complete vs
partial), Blackbox settings, DKG log and first-run onboarding.

The Avalonia window now uses the Axiom custom title bar (no native caption) with drag, double-click
maximize, minimize, maximize and close, on top of a native resizable border.

At 1080×720 the Avalonia shell fits all eleven navigation destinations and the Overview KPI row;
longer content scrolls inside its card. This addresses the baseline WPF clipping for the shell and
KPI row. The 125/150/200% DPI passes are still uncaptured.

Still outstanding:

- Windows 10 19044 DPI evidence at 125/150/200%.
- A controlled performance run with a fixed workload/resolution/mode/idle period.
- Hosted Linux/macOS CI verification for `.github/workflows/portable.yml`; the workflow exists but
  has not run on a hosted runner from this workstation.
- Installer/MSIX packaging and the separately approved release cutover.

A parity test package can be produced without touching the WPF release:

```powershell
dotnet publish src\Axiom.Desktop.Avalonia.Windows\Axiom.Desktop.Avalonia.Windows.csproj -p:PublishProfile=win-x64-selfcontained
```

The verified test artifact is a 52.4 MB self-contained single EXE in
`artifacts/publish/avalonia-win-x64/`, with `community/feed.json` copied beside it. The published EXE
started and answered as a normal window on this workstation. It is a test artifact, not a release.
