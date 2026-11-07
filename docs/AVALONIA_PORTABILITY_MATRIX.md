# Axiom — Avalonia Portability Matrix

Status: initial audit for the Windows-first migration
Baseline: `61d5520`
Audience: Windows implementer, followed by the Linux/macOS host contributor

This matrix classifies the current repository before any extraction. It does not add Avalonia
packages or projects. The goal is to make the boundary between portable presentation, WPF
replacement and Windows-only composition explicit.

## 1. Current project map

| Project | TFM | WPF/WinForms | Classification | Migration action |
|---|---|---|---|---|
| `Axiom.Contracts` | `net10.0` | no | shared/portable | retain |
| `Axiom.Core` | `net10.0` | no | shared/portable | retain |
| `Axiom.Persistence` | `net10.0` | no | shared SQLite | retain |
| `Axiom.McpServer` | `net10.0` | no | shared local MCP host (not in handoff target list) | retain, do not fold into UI |
| `Axiom.Infrastructure.Windows` | `net10.0-windows` | no | Windows backend | retain |
| `Axiom.Service` | `net10.0-windows` | no | Windows service host | retain |
| `Axiom.UI` | `net10.0-windows` | WPF | old presentation + page logic | extract, then retain as fallback |
| `Axiom.Desktop` | `net10.0-windows` | WPF + WinForms | old Windows composition root | retain; add Avalonia Windows host |
| `Axiom.Setup` | `net10.0-windows` | WPF | installer | retain until an explicit cutover decision |
| `Axiom.UI.Tests` | `net10.0-windows` | WPF references | old UI tests | retain; add portable/headless suites |

## 2. Target project map

```text
src/
  Axiom.Contracts/                  net10.0        DTOs and contracts
  Axiom.Core/                       net10.0        domain/firewall port
  Axiom.Persistence/                net10.0        SQLite
  Axiom.McpServer/                  net10.0        existing local MCP host
  Axiom.Presentation/               net10.0        NEW: view models, commands, state, formatting
  Axiom.UI.Avalonia/                net10.0        NEW: AXAML views, styles, drawing controls
  Axiom.Desktop.Avalonia.Windows/   net10.0-windows NEW: composition root + Windows shell adapters
  Axiom.Infrastructure.Windows/     net10.0-windows unchanged
  Axiom.Service/                    net10.0-windows unchanged
  Axiom.UI/                         net10.0-windows WPF fallback until cutover
  Axiom.Desktop/                    net10.0-windows WPF fallback until cutover
  Axiom.Setup/                      net10.0-windows installer, retained initially

tests/
  Axiom.Presentation.Tests/         net10.0        NEW
  Axiom.UI.Avalonia.Tests/          net10.0        NEW headless tests
  Axiom.UI.Tests/                   net10.0-windows retained WPF baseline
```

Hard rule: `Axiom.Presentation` and `Axiom.UI.Avalonia` must not reference
`Axiom.Infrastructure.Windows`, `Axiom.Service`, `Axiom.Desktop`, `Axiom.Setup`, `System.Windows*`,
`UseWPF`, `UseWindowsForms` or Win32 P/Invoke.

## 3. WPF dependency scan

Scan of `src/Axiom.UI`, `src/Axiom.Desktop` and `src/Axiom.Setup`, C# and XAML:

| Symbol/search | Files | Hits | Interpretation |
|---|---:|---:|---|
| `System.Windows` | 64 | 702 | broad WPF coupling |
| `System.Windows.Forms` | 3 | 3 | tray/file-dialog/host coupling |
| `Dispatcher` | 8 | 17 | UI-thread assumptions in page logic |
| `WindowChrome` | 3 | 13 | custom native-window shell |
| `DependencyProperty` | 2 | 23 | custom WPF controls |
| `RoutedEvent` | 24 | 63 | XAML event/code-behind behavior |
| `DataGrid` | 11 | 156 | high-risk tables |
| `ListCollectionView` | 1 | 2 | WPF collection view/filtering |
| `CollectionViewSource` | 2 | 2 | grouped views |
| `MessageBox` | 8 | 50 | UI decision/confirmation calls in page code |
| `Application.Current` | 3 | 7 | WPF application lifetime |
| `Visibility` | 18 | 86 | WPF-specific state presentation |

ViewModels already carrying WPF/UI-thread references:

| ViewModel | Approx. hits | Portability concern |
|---|---:|---|
| `SecurityViewModel` | 20 | dispatcher, message boxes, dialogs, module actions |
| `AgentsViewModel` | 10 | dispatcher timers, clipboard, dialogs, blackbox UI state |
| `AppsViewModel` | 10 | message boxes, process actions, context actions |
| `FirewallRulesViewModel` | 9 | message boxes, file picker, dispatcher, rule state |
| `EventsViewModel` | 5 | dispatcher timers, save-file dialog |
| `AiAnalystViewModel` | 2 | UI thread/file dialog |
| `PrivacyShieldViewModel` | 2 | dispatcher timer/file picker |
| `LiveConnectionsViewModel` | 1 | dispatcher/UI state |
| `SupportViewModel` | 1 | clipboard/external launcher |

`MainViewModel` and `PageViewModel` are already close to portable, but `MainViewModel` owns page
construction and menu/theme behavior that needs a portable host abstraction.

UI services with WPF coupling:

- `ConnectionMonitor` — dispatcher/UI thread notifications.
- `TrafficEngine` — UI-thread sampling and chart-facing state.
- `ThemeManager` — WPF resource dictionary application.

## 4. File-level classification

### Shared / portable without rewrite

- `Axiom.Contracts`, `Axiom.Core`, `Axiom.Persistence`, `Axiom.McpServer`.
- DTOs, IPC message contracts, persistence schema, rule identity, scanner and policy logic.
- `PageViewModel`, most row models (`ConnectionRow`, `EventRowView`, `AppRow`, `AppGrouping`) after
  removing presentation-only types.
- `MainViewModel` page/status composition after page construction and theme/WPF services are
  injected.

### Extract to `Axiom.Presentation`, then adapt

| Area | Current location | Work needed |
|---|---|---|
| Page view models | `src/Axiom.UI/ViewModels` | remove `Dispatcher`, `MessageBox`, `System.Windows`, WPF timers and dialogs; inject dispatcher/UI services |
| Formatting/sorting/grouping | page VMs and `TrafficChartGeometry` | move pure helpers; keep behavior tests |
| Theme selection | `ThemeManager` | split portable preference model from visual theme application |
| Status/error/degraded state | page VMs | preserve exact labels and capability semantics |
| Command enablement | page VMs | keep `CanExecute` rules, especially firewall/agent trust gates |
| Copy/export | page code | inject clipboard/file-picker/external-link services |

### Replace with Avalonia views/styles

- All 19 `.xaml` files under `src/Axiom.UI/Views` and `.xaml.cs` code-behind.
- `MainWindow.xaml` and `MainWindow.xaml.cs` custom chrome.
- `Controls/TrafficChart.cs`, `TrafficChartGeometry.cs` (geometry can remain portable; renderer
  replaced).
- `Controls/ThreatGraphControl.cs` (native WPF renderer; replace with Avalonia renderer).
- `Themes/Dark.xaml`, `DarkMidnight.xaml`, `Light.xaml`, `LightWarm.xaml`, `Controls.xaml`.
- `App.xaml` resource dictionaries and typed data templates (`Axiom.Desktop/App.xaml`).

### Windows-only host / retain

- `Axiom.Infrastructure.Windows`: IP Helper, COM firewall, process identity, pipe ACL.
- `Axiom.Service`: monitoring/history/firewall/Privacy Shield service.
- `Axiom.Desktop/App.xaml.cs`, `Program.cs`, `TrayStatusController`, `BundledServiceHost`.
- `Axiom.Setup` WPF installer.
- Native file pickers, clipboard, tray, single-instance, window activation, DPI/OS integration.

## 5. Page migration units and risk

| Unit | WPF view size | Risk | Main portability issues |
|---|---:|---|---|
| Shell / MainWindow | 229 lines | high | WindowChrome, drag/snap, tray, single instance, theme selector, status strip |
| Overview | 662 lines | high | DataGrid activity, traffic chart, KPI/live states, copy menus |
| Connections | 332 lines | high | virtualized table, filtering/grouping, selection/scroll retention |
| Applications | 297 lines | medium | grouped list, context menus, firewall-write confirmation |
| Events | 289 lines | high | DataGrid, paging, export file dialog, history semantics |
| Firewall | 371 lines | high | rule editor, write gate, read-back, defaults, file picker |
| Security | 312 lines | high | modules, file scan, reputation, community, agent hooks, dialogs |
| Privacy Shield | 326 lines | high | resolver state, source catalog, UAC adapter helper, blocked history |
| Agents | 839 lines | very high | Blackbox/DKG, graph, activity/findings, hook evidence, sessions, auto-sync |
| AI Analyst | 188 lines | medium | opt-in provider/key, redaction, local settings |
| Support | 114 lines | low | external links, donations, copy actions |
| Settings | 184 lines | low/medium | theme, tray, autostart, build/runtime info |
| Dialogs (7) | 20–182 lines | medium | modal behavior, validation, consent, UAC errors |

## 6. Controls and data strategy

### Tables

WPF `DataGrid` is used in 11 files and is a high-risk migration area. The current WPF
pages rely on selection, sorting, grouping, context menus, scroll retention and fast refreshes.

Decision required in the Avalonia spike:

- evaluate `Avalonia.Controls.DataGrid` license/status and current maintenance;
- compare with a virtualized `ListBox`/`ItemsControl` composition if DataGrid is not the best
  maintained free option;
- do not add paid Avalonia Pro `TreeDataGrid` or proprietary controls;
- preserve grouping/filtering in portable collection models rather than view-only WPF
  `CollectionViewSource`.

### Charts and verified graph

- Traffic chart: retain `TrafficChartGeometry` as portable math; reimplement rendering in Avalonia
  drawing primitives.
- Verified threat graph: retain graph layout/model concepts, replace WPF `DrawingContext` rendering.
- No WebView/Chromium for charts or graph unless a separate architecture review justifies it.
- Keep system-wide counters honestly labelled; do not invent per-process bytes.
- Preserve graph semantics: verified/community/unknown/offline, severity, provenance.

### Themes and assets

- Port the four theme palettes and semantic brush names; WPF resource keys are not drop-in
  Avalonia resources.
- Replace `/Axiom.UI;component/...` and `pack://application:,,,` URIs with Avalonia asset URIs.
- Avoid depending on `Segoe MDL2 Assets` for portable UI; use a permissively licensed icon source or
  vector assets and retain notices.
- Keep `.ico` for the Windows shell; portable icon assets for future hosts.

## 7. Windows host contract

The Avalonia Windows host must own:

- existing authenticated named-pipe client and typed IPC commands (no new HTTP/localhost bypass);
- service startup/detection and read-only fallback semantics;
- Windows IP Helper and firewall adapter composition, unchanged;
- tray icon/menu, notifications, single instance, native dialogs, clipboard, URL opening;
- Windows DPI/window behavior;
- installer/distribution context and package assets.

The portable UI must receive capability and protection state only through contracts. It must not
open firewall or DNS write paths directly, install hooks, or call arbitrary processes.

## 8. Dependency and license audit

Current central packages (`Directory.Packages.props`) are MIT/Apache-compatible: CommunityToolkit.Mvvm
8.4.2, Microsoft.Data.Sqlite 10.0.14, Microsoft.Extensions.Hosting.WindowsServices, Microsoft.NET.ILLink.Tasks,
ModelContextProtocol 2.3.1, Microsoft.Extensions.Hosting, xUnit and test SDK packages.

Before adding Avalonia:

- verify the selected stable Avalonia release and its MIT license;
- pin exact versions in `Directory.Packages.props`, never wildcards;
- review the license and maintenance of the specific DataGrid package;
- avoid Avalonia XPF, paid Pro/Plus controls and proprietary themes;
- audit transitive licenses and notices for fonts/icons;
- commit compatible `packages.lock.json` changes.

## 9. CI and test target

Portable gate (to be created from actual projects):

```text
Axiom.Portable.sln
  Axiom.Contracts
  Axiom.Core
  Axiom.Persistence
  Axiom.McpServer
  Axiom.Presentation
  Axiom.UI.Avalonia
  Axiom.Presentation.Tests
  Axiom.UI.Avalonia.Tests
```

Required CI checks:

- Windows: legacy WPF build/tests + portable tests + new Windows Avalonia host build;
- Linux/macOS: portable solution only; no `-windows` TFM and no WPF/WinForms references;
- grep/guard check for `System.Windows`, `UseWPF`, `UseWindowsForms` in portable projects;
- headless Avalonia tests for navigation, bindings, themes, table selection and disconnected state;
- locked restore once the lock/RID issue is resolved.

## 10. Open decisions before extraction

1. DataGrid versus a custom virtualized list after the Avalonia spike.
2. Exact Avalonia stable version and compatible DataGrid package version.
3. Tray/notification abstraction shape for Windows and future hosts.
4. Whether the setup UI migrates in this phase or remains WPF until after Windows UI parity.
5. How much of the existing WPF code-behind becomes portable commands versus host services.
6. The responsive layout contract for 1080 × 720, where baseline screenshots show clipping.
7. Whether `Axiom.McpServer` remains a sibling portable project (recommended) or later gains a
   separate host integration.

## 11. Step 2 exit condition

The portability audit is complete when:

- every WPF project/file group has an owner: shared, extract, Avalonia replacement, Windows host or
  fallback;
- no ambiguous dependency remains in the proposed `net10.0` projects;
- high-risk controls and native shell pieces have explicit spike/decision tasks;
- the license decision is recorded;
- portable CI can be described without assuming the Windows solution builds on Linux/macOS.

Initial extraction: `Axiom.Presentation` now contains the portable page base, UI timer/dispatcher
contracts, connection monitor, traffic engine and pure row/geometry/formatting models. The WPF page
view models and views have not yet been moved; the old UI remains the reference and fallback.
