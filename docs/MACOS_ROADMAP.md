# Axiom for macOS — improvement roadmap (product review, 2026-11-11)

Second review, product lens: feature gaps vs Little Snitch 6 / LuLu 3, Windows parity, macOS UX, optimisations.
Security/correctness findings live in `MACOS_REVIEW.md` (all closed). Sources: obdev.at Little Snitch 6
"What's new" and rule/profile help, objective-see.org LuLu, Radio Silence and Lockdown FAQs.

## Top 5

1. **Native Shield alerts** at connect time via `UNUserNotificationCenter` (Swift host/extension export,
   Allow/Block actions). Today the ask only lands on the Firewall page plus an in-house toast. Biggest perceived gap.
   Effort M.
2. **Rules by code-signing identity + hostname rules** (`rules.json` schema v2: `signingId`/`teamId`, `remoteHosts`
   with suffix match). The filter already has `remoteHost` and the daemon already parses signers. Fixes rule breakage
   on app updates and App Translocation; gives domain-level control. Hostname is best effort (only Network.framework
   clients set it, same caveat LuLu documents). Effort M.
3. **Silent/learning mode + temporary rules** (`AskMode: ask|silent`, `RuleSpec.ExpiresUtc`, "allow for 15 min /
   until quit"). Removes the first-run prompt flood. Effort S.
4. **Native-conventions pass**: Cmd+, Settings, `SMAppService` login item (shows in System Settings), Dock/menu-bar-only
   toggle (`ShowInDock`), live dark-mode via `RequestedThemeVariant=Default`, menu-bar live throughput + last blocked,
   hide Windows profile checkboxes (Domain/Private/Public) on macOS. Effort S each.
5. **Startup/size**: `PublishReadyToRun` + `InvariantGlobalization` now (safe); trimming after switching to compiled
   bindings; one shared .NET runtime for app and daemon (saves ~60 MB); stop libproc polling while the filter streams;
   back off UI snapshots when the window is hidden.

## A. Feature gaps vs Mac firewalls (ranked)

| # | Gap | Value | Effort | Plugs in |
|---|---|---|---|---|
| 1 | Shield ask as native alert with app, signer, destination | High | M | `App.axaml.cs` + dylib `axiom_notify` |
| 2 | Hostname/domain rules (`*.example.com`) | High | M | `RuleTable.swift`, `FilterRuleTable.cs`, `RuleSpecValidator` |
| 3 | Code-signing identity rules (Team ID / signing id) | High | M | `FlowInspector` via `SecCodeCopyGuestWithAttributes`, `MacProcessIdentityResolver` |
| 4 | Silent/learning mode; "Apple system services" rule group | High | S | `ProtectionSettings.AskMode` |
| 5 | Temporary rules (until quit / 15 min) | Med-High | S | `RuleSpec.ExpiresUtc`, daemon prune timer |
| 6 | Menu-bar control centre: throughput, last 5 blocked, pause filter, silent toggle | Med | S-M | `CreateTrayIcon` dynamic items |
| 7 | Profiles with automatic switching by network | Med | L | Defer (SSID needs Location permission on 14+) |
| 8 | Rule import/export incl. Little Snitch `.lsrules` | Med | S | Firewall page export; LS JSON mapping |
| 9 | `axiomctl` CLI, Shortcuts, Mac-worded MCP tool text | Med | S | `IpcPipeClient` reuse; `PlatformText` for MCP |
| 10 | `localNetwork` matcher (RFC1918 + link-local); inbound listing with port | Med | S | `RuleTable.swift` token |
| 11 | Per-rule hit counts; "block this host only" from the alert; DoH/DoT upstream for Privacy Shield | Low-Med | S/S/M | `FlowTable` ruleId counts; `DnsProxyServer` |

## B. Windows parity still missing on macOS

- DKG / Blackbox guided installers return "not available on macOS yet" (shell + Homebrew/npm path, effort M).
- Agent-protection hook locations assumed `~/.<tool>` for Claude/Codex/Cursor/Windsurf/Cline etc.; verify per tool
  in the VM (S each).
- AI Analyst evidence is thinner: parent-process chain empty off Windows (`AiEvidenceContext.cs:332`), no signer.
  Wire `MacProcessIdentityResolver` + `proc_pidinfo` ppid chain (S).
- OpenCode/OpenChamber `.app` not probed (S). ICMP option should be greyed on macOS (S).
- MCP server not packaged in `Axiom.app`; descriptions say "Windows Filtering Platform" (S).
- Overview says "Per-app rates require separate telemetry" (Windows ESTATS caveat) although `flow.stats` already
  provides per-app bytes on macOS (S).

## C. macOS UX

1. Not native-feeling: custom header row under the title bar, logo/GitHub/Donate block in the sidebar, theme dropdown
   on every page. Mac convention: unified toolbar, source-list sidebar, theme in Settings. (M)
2. No Cmd+, / "Settings…" in the app menu; wording "tray icon" → "menu bar icon", "Start minimized" →
   "Open in background", "Repair startup entry" is Windows jargon. (S)
3. Application menu shows Avalonia's default instead of the custom `NativeMenu` in the VM; AppleScript quit −128. (S-M)
4. Login item via LaunchAgent plist; macOS 13+ expects `SMAppService.loginItem` so it appears in System Settings. (S)
5. No "Show in Dock" toggle (`LSUIElement` / activation policy). (S)
6. Dark mode read once at start; use Avalonia's system tracking. (S)
7. Dense disclaimer paragraphs on Firewall/Agents/Privacy Shield; "End task" → "Quit process"; Block/Allow buttons
   above the list instead of per row/context menu; empty PROFILES/STATE columns; first-run dialog dark on a light app
   and labelled "development build". (S-M)
8. Connections rows show `com.apple.geod` and long framework paths; add `CFBundleName` + `NSWorkspace` icons. (M)
9. Blocked = 30 s hang; the blocked-flow notification (A1) is the mitigation.
10. Overview banner "Read-only inventory…" and sidebar "LIVE · READ-ONLY" still shown with Shield ON. (S)

## D. Optimisations

| Item | Value | Effort | Risk |
|---|---|---|---|
| `PublishReadyToRun=true` app + daemon | cold start −30–50 % JIT | S | low (+~30 % size) |
| `PublishTrimmed` after `AvaloniaUseCompiledBindingsByDefault=true` (2 files use ReflectionBinding) | app 110→~50 MB, daemon 81→~35 MB | M | medium: runtime XAML/reflection breaks; re-run headless tests on the published tree |
| One shared .NET runtime (`Contents/Frameworks/dotnet`, `DOTNET_ROOT` in the plist; copied to the root-owned helper dir too) | −~60 MB | M | medium |
| `InvariantGlobalization=true` | −20 ms, −5 MB | S | low |
| UI polling: snapshot 1 s + traffic 1 s + privacy 2 s + agents 8 s + security 5 s, each a full JSON snapshot | lower idle CPU/IPC | S-M | low: push deltas, back off when window hidden |
| Daemon: stop libproc scan while the filter is connected (`FlowTable` authoritative) | fewer syscalls | S | low |
| DNS rediscovery spawns `scutil` every 10 s | 6 processes/min | S | low: `SCDynamicStore` notification or 60 s + on-failure |
| Rate-limit repeated identical log lines (`Privacy Shield DNS:`, `Denied`) | log volume | S | low |
| Build: dual TFM doubles `Axiom.Service` builds; use `-f net10.0` lanes | CI time | S | low |
| Measure daemon RSS with Privacy Shield policy loaded (Windows README cites ~190 MB) | unknown | S | — |
