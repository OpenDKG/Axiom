# Windows notification area — measured throughput and monitoring faults

This Draft feature stacks on PR #99, #97 and #96.

## What it does

- Adds a lightweight tray icon to Windows' notification area next to the clock for the **running** Axiom desktop process. Windows may hide it under the notification overflow menu until the user pins it.
- The icon displays two directional arrows; hovering over it reports **measured** system-wide upload and download rates in B/s, KB/s, MB/s or GB/s with autoscaling. No fabricated application-level traffic attribution.
- Left click/double click opens the app. Right click shows the live rates, monitor health, an Open action, a notification toggle and Exit.
- A red exclamation overlay is shown **only** when the existing socket monitor reports an error or an established connection snapshot is stale. New connections alone are never treated as threats.
- The optional Windows shell notification is raised **once per transition** into an observed monitoring fault (not every poll). These are best-effort `NotifyIcon.ShowBalloonTip` notifications; modern Windows may turn them into system notifications, and Windows focus-assist/policy controls can suppress them.
- **Notifications and the tray icon are separate.** `Show notifications` controls alerts and persists
  in `%LOCALAPPDATA%\Axiom\notifications.txt`; `Show tray icon` controls the notification-area icon
  and close-to-tray behaviour and persists in `%LOCALAPPDATA%\Axiom\tray-notifications.txt`. Disabling
  notifications does not hide the problem icon, and the in-app alert history still records every
  event.
- **Hide background console windows** hides console windows of helper processes launched by Axiom
  (Node, cmd, PowerShell, Python, DKG, OpenCode and conhost). It only follows descendants of the
  desktop process, never an unrelated process that merely shares a name. It persists in
  `%LOCALAPPDATA%\Axiom\hide-background-windows.txt`. UAC and interactive third-party installers stay
  visible by design.
- Status information comes from the existing UI `TrafficEngine` and `ConnectionMonitor`; no extra telemetry polling. No remote upload, no firewall changes.
- Closing the app hides it to the notification area while **Show tray icon** is enabled and exits when
  it is disabled. Minimize keeps the app running normally. Autostart is opt-in from Settings (off by
  default); the Run entry uses `--autostart`, and Start minimized uses `--start-minimized`. A second
  launch focuses the existing instance instead of starting another tray/service.

## What it does *not* do

- Does not yet detect or validate malware, intrusion, suspicious IP or agent compromise. Those security alerts require a separate evidence-bearing event pipeline. A red exclamation currently means **monitoring fault**.
- Cannot reliably fit live numeric rates onto the 16x16 tray glyph; exact measurements are in the tooltip and menu. The glyph itself uses directional arrows.
- Does not use a full packaged Windows App SDK toast/Action Center integration or persistent push-notification history.

## Windows-only validation gate

1. `dotnet restore Axiom.sln --locked-mode`, `dotnet build Axiom.sln -c Release --no-restore` and `dotnet test Axiom.sln -c Release --no-build`.
2. Test rate strings by downloading/uploading real traffic and compare to Overview's measured counters, including KB/s, MB/s and idle/unknown states.
3. Test no balloon spam on repeated errors, red icon on known monitor errors, recovery resets icon, and notification suppression.
4. Check icon and menu behavior on Windows 10/11, shell DPI changes, overflow tray behavior and app close/restart.
5. Confirm App shutdown removes tray icon and GDI icon handles do not grow after refreshes.
6. Ensure no modifications to Codex/OpenChamber/OpenCode/Hermes data, junctions, agent sessions or firewall rules.

**Status:** Code authored; Windows compilation, GUI test and integration tests not executed here.
