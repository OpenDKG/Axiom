# Axiom — Cross-Platform UI Handoff

Status: Windows-first Avalonia migration in progress; WPF remains the release application.
Branch: `feature/avalonia-windows-first`
Audience: the Linux/macOS contributor who will add platform hosts after the Windows port reaches
parity and the cutover is approved.

## 1. What exists now

```text
src/
  Axiom.Contracts/                  net10.0        shared DTOs and IPC protocol
  Axiom.Core/                       net10.0        domain and firewall port
  Axiom.Persistence/                net10.0        SQLite
  Axiom.McpServer/                  net10.0        local MCP host
  Axiom.Presentation/               net10.0        portable view models, state, service boundary
  Axiom.UI.Avalonia/                net10.0        AXAML views and Avalonia host services
  Axiom.Desktop.Avalonia.Windows/   net10.0-windows Windows composition root
  Axiom.Infrastructure.Windows/     net10.0-windows Windows monitoring/firewall backend
  Axiom.Service/                    net10.0-windows Windows service
  Axiom.UI/                         net10.0-windows WPF fallback
  Axiom.Desktop/                    net10.0-windows WPF fallback
  Axiom.Setup/                      net10.0-windows installer, retained until cutover

tests/
  Axiom.Presentation.Tests/         net10.0        portable state and service boundary
  Axiom.UI.Avalonia.Tests/          net10.0        page/state tests without a render pass
  Axiom.UI.Tests/                   net10.0-windows WPF baseline (reference)
```

`Axiom.Presentation` and `Axiom.UI.Avalonia` must never reference `Axiom.Infrastructure.Windows`,
`Axiom.Service`, `Axiom.Desktop`, `Axiom.Setup`, WPF, WinForms or Win32 P/Invoke. The Windows host
supplies those implementations through the interfaces in `Axiom.Presentation`.

## 2. Portable contracts a new host must implement

| Interface | Purpose | Windows implementation |
|---|---|---|
| `IUiTimerFactory` / `IUiTimer` | UI-thread repeating timers | `AvaloniaUiTimerFactory` |
| `IUiDispatcher` | UI-thread dispatch | `AvaloniaUiDispatcher` |
| `IServiceRequestClient` | typed local service commands | `ServicePipeClient` (named pipe) |
| `IUserInteraction` | confirm, message, save/open dialog, clipboard, external link | `AvaloniaUserInteraction` |
| `IProcessActions` | end confirmed process tree | `ProcessActions` |
| `IThemeService` | apply/persist Dark or Light | `WindowsThemeService` |
| `IAutostartService` | per-user startup entry | `WindowsAutostartService` |
| `IApiKeyProtector` | protect the optional AI key at rest | `DpapiApiKeyProtector` |
| `IDnsAdapterHelper` | UAC-gated adapter DNS change/restore | `WindowsDnsAdapterHelper` |

A host that cannot provide one of these must use the matching `Unsupported*` or `Null*` fallback.
The fallbacks never fake success and never write plaintext secrets.

## 3. Service boundary

The UI never reads the service database. It sends only the commands listed in
`Axiom.Contracts.Ipc.IpcCommandTypes` over the local pipe. Unknown commands, remote clients and
generic exec are not part of the protocol.

- `snapshot` returns the current `ConnectionSnapshot`.
- `capabilities` and `serviceHealth` drive the footer state.
- `history.query` drives Events.
- `rules.query`, `rule.apply`, `rule.remove` drive Firewall/Applications.
- `privacy.status`, `privacy.configure`, `privacy.sources.update`, `privacy.history.clear` drive
  Privacy Shield.

A Linux/macOS service will need its own backend that implements the same DTOs. Firewall and
monitoring backends for Linux/macOS are explicitly out of scope for the Windows-first stage.

## 4. Build and test

```powershell
dotnet restore Axiom.sln --locked-mode
dotnet build Axiom.sln -c Release --no-restore
dotnet test Axiom.sln -c Release --no-build --no-restore
```

Portable-only gates:

```powershell
dotnet restore Axiom.Portable.slnx --locked-mode
dotnet build Axiom.Portable.slnx -c Release --no-restore
dotnet test Axiom.Portable.slnx -c Release --no-build --no-restore
```

`Axiom.Portable.slnx` deliberately excludes every Windows-only and WPF project. It is the first
signal that a change has broken portability.

## 5. Running the Avalonia Windows host

```powershell
# in-process, read-only monitoring
src\Axiom.Desktop.Avalonia.Windows\bin\Release\net10.0-windows\Axiom.Desktop.Avalonia.Windows.exe

# use the local service
...\Axiom.Desktop.Avalonia.Windows.exe --service

# start hidden in the tray
...\Axiom.Desktop.Avalonia.Windows.exe --start-minimized
```

The host starts the bundled `Axiom.Service.exe` when it sits next to the desktop executable, reuses
an already running service, and falls back to the in-process IP Helper source otherwise. The footer
shows `Data source`, `Database`, `Firewall writes` and `IPC` separately so an offline service is
never rendered as live protection.

## 6. Security rules for new work

- Keep local-only defaults. Do not add telemetry, uploads, cloud calls or automatic hooks.
- Preserve the explicit service write gate before any firewall change.
- Preserve per-action confirmation and audited read-back for rule changes.
- Never synthesize DNS, traffic, history or protection state. Show `unavailable` instead.
- Do not claim a hook installed by Axiom is blocking until runtime evidence proves it.
- Keep screenshots of live activity out of Git; they contain private local process data.
- Do not move `Axiom.UI`/`Axiom.Desktop` out of the solution until parity and a separate cutover
  approval.

## 7. Remaining before cutover

1. Replace native Windows chrome with the Axiom custom title bar and native snap behaviour.
2. Add 125/150/200% DPI evidence at 1080×720 and 1460×900.
3. Add Linux/macOS CI that builds/tests `Axiom.Portable.slnx` only.
4. Measure performance with a fixed workload, resolution, mode and idle period.
5. Build an installer test package and run a separate cutover review.

## 8. Adding a Linux/macOS host later

Create `Axiom.Desktop.Avalonia.Linux` (and `.MacOS`) as `net10.0` host projects referencing
`Axiom.UI.Avalonia`, `Axiom.Presentation` and the platform backend. Implement the host interfaces
in section 2. Do not reference any Windows project. Add a platform service project implementing the
IPC DTOs; keep the pipe/transport abstraction behind `IServiceRequestClient` so the UI does not know
whether the transport is a named pipe, Unix socket or local HTTP loopback.

The UI project should need no changes for a new host beyond a platform-specific `TrayIcon` icon and
the native file dialog/clipboard implementations already abstracted by `IUserInteraction`.
