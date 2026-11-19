# Axiom for macOS — port report for the maintainer

Date: 2026-11-13 (updated after the GitHub review of PR #274). Branch `buba/macos` on top of `main` **2a834c2 / v0.16.0**
(merged 2026-11-13 as `e07f112`; earlier bases v0.13.2 6ff6061 → `79f4ff3`, v0.13.0). Review remediation commits: `b200c00` (IPC authorization,
P0 #1), `7b2a95b` (rule lifecycle + filter status, P0 #2/#3, High #4), `5dd4532` (log permissions, Medium #5); see
`docs/MACOS_REVIEW.md` "GitHub review 2026-11-12" and `docs/pr274-review-replies.md`.
Scope: 248 files, +23.9k / −1.7k lines. Shared (Windows-relevant) code: 99 files, +2.6k / −2.2k, mostly
extraction into portable projects. The WPF projects (`Axiom.UI`, `Axiom.Desktop`) are untouched except 26 lines.

Detailed docs in the branch: `docs/MACOS_ARCHITECTURE.md` (contract + as built), `docs/MACOS_TEST_REPORT.md`
(rows A–AE with evidence), `docs/MACOS_REVIEW.md` (two independent reviews, all 25 findings ticked with commit
ids), `macos/README.md` (Swift filter), `docs/screenshots/macos/` (every page).

## 1. What was accomplished

Axiom runs on macOS with the same shared Core/Contracts/Persistence/Presentation/UI.Avalonia code as Windows,
plus three macOS-specific pieces:

| Piece | Windows counterpart | Where |
|---|---|---|
| `Axiom.app` desktop host (Avalonia, menu-bar icon, native menu, Keychain, LaunchAgent autostart, single instance) | `Axiom.Desktop.Avalonia.Windows` | `src/Axiom.Desktop.Avalonia.MacOS` |
| `axiomd` launchd root daemon (same `Axiom.Service` project, `net10.0` target) | Windows service | `src/Axiom.Service` + `src/Axiom.Service.Hosting` + `src/Axiom.Infrastructure.MacOS` |
| `com.axiom.firewall.filter` NEFilterDataProvider system extension (Swift) + `axiom-sysext` helper + `libAxiomSysext.dylib` | Windows Firewall rules | `macos/` |

Verified end to end in a macOS 15.8.3 VM through the app's own UI (all PASS):
service install via admin prompt (≈3 s), filter activation + approval, live Connections with app names,
block an app from Connections → `curl` blocked while `python3` to the same host works, unblock from the
Firewall page, Privacy Shield on/off (system DNS → 127.0.0.1, `doubleclick.net` NXDOMAIN, DNS restored),
every page rendered, menu-bar icon, quit/relaunch/single instance, upgrade in place, uninstall.

Security hardening done after an independent review and the GitHub review of PR #274: daemon copied to a root-owned
`/Library/PrivilegedHelperTools/com.axiom.service/` and verified before launch; IPC authorization in four layers
(connect / public read / private read / write — root and the installing user get everything, `admin` members per
`AllowAdminGroupWrites`, every other local account only a redacted `serviceHealth` + `capabilities`, unknown peer
credentials closed); data dir 0700 / files 0600; daemon log dir 0700 / log + archives 0600 (newsyslog 600); rules file
must be root-owned and not group/world-writable; per-uid connection cap; `axiomd --doctor` self-check;
upstream's `axiomd --recover-network [--apply]` offline recovery (v0.11.0) wired to macOS.

Enforcement is reported truthfully (upstream `docs/ENFORCEMENT.md`): a rule written to `rules.json` is `Pending` until
the extension acknowledges that generation over a live connection (`filter.rules` without error), `Applied` only then
(verified at the ack time), `Failed` with the filter's reason when it rejects the rule or the file; `rule.verify` has an
`effectiveAction` only while verified; `capabilities` reports `connected`, `publishedGeneration`, `ackedGeneration`,
`lastSeenUtc`, `lastAckUtc` and goes `degraded` the moment the extension disconnects (no "seen recently" window).
Design: `docs/MACOS_ARCHITECTURE.md` §5.4 (authorization) and §5.7 (lifecycle state machine).

Gate on Linux (after the v0.13.0 merge): `dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` 0 errors / 0 warnings.
Tests: Contracts 142, McpServer 33, Persistence 19, Presentation 90, UI.Avalonia 40, Infrastructure.MacOS 155,
Desktop.Avalonia.MacOS 35 pass; Swift filter 147 checks + 61 e2e checks pass in the VM. Pre-existing Linux-only
failures are byte-identical to upstream `origin/main` run on the same host: Core 11/128 (Windows paths); Service and
Infrastructure.Windows suites are Windows-only.

## 2. What changed in shared code (Windows must stay byte-identical; it does, by test)

- `Axiom.Contracts.AxiomPaths`: single source for machine/user data roots and service-mode detection.
  Windows results unchanged (`%ProgramData%\Axiom`, `%LocalAppData%\Axiom`, `!UserInteractive`).
  Unix: `/Library/Application Support/Axiom`, `~/Library/Application Support/Axiom`, service = `AXIOM_SERVICE=1` or euid 0.
- `IpcPipe.Endpoint`: pipe name on Windows, `/var/run/axiom/axiom.sock` on Unix. `IpcPipeClient` uses it.
- `Axiom.Service.Hosting` (new, portable): `IpcRequestDispatcher` + handlers extracted from `PipeServer`
  (which is now transport only, old constructor kept), `DnsProxyServer`/`DnsProtocol` moved here, seams
  `IIpcTransport`, `IPrivacyDnsPlatform`, `IDnsAppAttributor`. `ProtectionWriteConsent` + new
  `FirewallWriteGate` moved to `Axiom.Core/Firewall`. Windows wrappers: `NamedPipeIpcTransport`,
  `WindowsDnsProcessLookup`, `WindowsPrivacyDnsPlatform`.
- `Axiom.Service` multi-targets `net10.0-windows;net10.0`; Windows-only files excluded from `net10.0`;
  per-OS wiring in `ServicePlatform.Windows.cs` / `ServicePlatform.Unix.cs`.
- Contracts additions (null on Windows): `LiveConnection.RemoteHost`, `ProtectionSettings.AllowedUid`,
  `FirewallCapabilityReport.FilterEnforcement`, `EffectiveRuleReport.FilterRejectionReason`.
- `Axiom.Presentation`: `PlatformText` (macOS wording), `MacElevation`, `AgentPlatform` (POSIX hook scripts,
  no `.exe`), `OptionalModuleInstaller/Uninstaller` return "not available on macOS" off Windows.
- `Axiom.UI.Avalonia`: native window chrome off Windows, vector icons instead of Segoe glyphs, selection kept
  across the 1 s refresh (fixes "Block outbound" doing nothing), Firewall page refresh on open + rejected-rules
  block, Events toolbar columns, one file re-encoded from cp1252 to UTF-8.
- `Axiom.sln` / `Axiom.Portable.slnx` gained the MacOS projects and tests.

Merge of upstream v0.11.0 (`3aaaad5`, 120 commits: security hardening 0.10.7, network recovery stages 1–4, Glass UI,
disk write budget, DoH bypass detection, …) — conflicts in 9 source files + 6 lock files, resolved so that Windows keeps
upstream's logic and the macOS seam is re-applied on top:

- `IpcRulePolicy` (reject inbound allow on the pipe, 40d560f) moved from `Axiom.Infrastructure.Windows/Ipc` to
  `Axiom.Service.Hosting/Ipc` (namespace change only) and is enforced in `IpcRequestDispatcher`, with upstream's
  `networkRecovery.capture/restore` commands (payload must be empty), so both transports behave the same. The DNS reply
  validation of 40d560f already lives in the portable `DnsProtocol`/`DnsProxyServer`.
- `Program.cs` keeps upstream's shape; `ServicePlatform.{Windows,Unix}` gained `HardenMachineState()`
  (Windows: `MachineStateSecurity.HardenProgramData` + `ServiceImageProtection`; macOS: `MacDataDirectoryPermissions`),
  `RecoverySnapshotPath`, the `IOwnedRuleRecoveryAdapter`/`INetworkRecoveryDnsAdapter` registrations and the five
  hooks `NetworkRecoveryCommand` needs (`AttachParentConsole`, `IsAdministrator`, `IsServiceProcessRunning`,
  `CreateRecoveryAdapters`, `CurrentActor`). The Windows hook bodies are upstream's code moved verbatim.
  `MachineStateSecurity.cs`, `ServiceInstaller.cs`, `ServiceImageProtection.cs` are excluded from `net10.0`;
  `Platform/MachineStateSecurity.Unix.cs` provides `IsReparsePointInPath` only.
- `NetworkRecoverySnapshotStore`: temp file gets 0600 before the atomic move off Windows (same pattern as
  `ProtectionSettingsStore`, which now combines upstream's random temp name with the mode).
- `PrivacyShieldBlockedHistoryStore`: upstream's batched append + 0600 on first create. `HistoryStore`'s 0600 sweep is
  unaffected by the batched writer (5e5ec21).
- `PrivacyShieldController`: upstream removed the threat-share hook and added `EnrichProvenance`; our
  `IPrivacyDnsPlatform` parameter kept. `PrivacyShieldWorker` calls `dnsPlatform.RestoreIfNeeded()` where upstream calls
  the static `PrivacyDnsFailSafe`.
- `MainWindow.axaml`: upstream Glass UI chrome values (margins, 22 px icon, 44 px bell row) with our `x:Name` hooks; the
  off-Windows native-chrome/vector-icon code is untouched. Page subtitles: upstream copy with `PlatformText.HostKind`.
- `PipeServer`: ours (transport only); the old constructor gained the two recovery delegates so upstream's
  `PipeServerTests` compile unchanged.

Merge of upstream v0.13.0 (`e45f880`, 4 commits: 0.12.0, Antigravity UI/UX overhaul + full context menus +
v0.12.0 network recovery fixes, 0.13.0) — conflicts in 6 views, resolved with upstream's XAML and only the
off-Windows bits re-applied:

- `AiAnalystView`, `PrivacyShieldView`, `FirewallView`: `PlatformText` bindings (API-key placeholder, adapter DNS
  title, firewall rules title, ask-queue explanation) on upstream's new `section-title`/`mono` styles.
- `FirewallView`: the macOS-only filter banner + rejected-rules block (`FilterEnforcementSummary`) under the status
  line, restyled to upstream's radii/font sizes. `SecurityView`: `DisplayGlyph`. `EventsView`: toolbar gaps.
- `ConnectionsView`: upstream now binds grouped rows' `SelectedItem` TwoWay to `SelectedConnection`, which is what
  our `OnGroupRowSelectionChanged` handler did; the handler is gone and the code-behind is upstream's.
- Network recovery contract (v0.12.0): `NetworkRecoveryController.SameServers` and `WindowsDnsRecoveryAdapter` are
  now order-sensitive, so `MacDnsRecoveryAdapter` compares resolver lists in order too (`networksetup` preserves
  order). The controller's new re-hardening after a capture into the default location
  (`MachineStateSecurity.HardenProgramData`, a Windows-only file here) goes through
  `ServicePlatform.HardenRecoverySnapshotLocation()`: Windows calls `HardenProgramData()` verbatim, macOS re-asserts
  0700/0600 via `HardenMachineState()`. `NetworkRecoveryCommand`'s new reparse-point refusal is a no-op off Windows
  by upstream's own guard. `IOwnedRuleRecoveryAdapter` / `ServicePlatform.Unix` hooks are unchanged.
- VM smoke after the merge (osx-x64, unsigned): daemon `state = running`, `serviceHealth` ok, `rule.apply` on
  `/usr/bin/curl` → `curl` rc 7, `rule.remove` → HTTP 200; `screenshots/macos/connections-v0.13.0.png`,
  `firewall-v0.13.0.png`.

## 3. macOS-specific notes the maintainer must know

Platform behaviour
- **Enforcement is a Network Extension, not pf.** pf has no per-app concept and the Application Firewall is
  inbound-only. The Swift extension holds its own rule table (`filter/rules.json`, written by the daemon) and
  streams flow events over `/var/run/axiom/filter.sock`. Core is unchanged; `MacFirewallPolicyAdapter`
  implements `IFirewallPolicyAdapter`.
- **Blocked TCP = connect timeout, not refusal.** NE drop verdicts swallow the SYN; apps see a ~30 s hang.
  ICMP is not filterable. Unconnected UDP sockets get one verdict for the socket.
- **Enabling, disabling or upgrading the filter drops TCP connections opened while it ran**, including SSH.
  The app warns; upgrades over SSH must be detached.
- **First approval needs the GUI session**: System Settings › General › Login Items & Extensions › Network
  Extensions, then the "Filter Network Content" prompt. Deactivation over SSH fails (error 13).
- **Attribution is the socket owner.** Safari/WebKit and `nsurlsessiond` traffic belongs to the network
  process, not the app. The filter also reports and matches the *responsible* process
  (`responsibility_get_pid_responsible_for_pid`, private API, LuLu-proven); App Translocation paths of
  quarantined apps will not match `/Applications/...` rules. Paths are compared case-insensitively on realpath.
- **Loopback is exempt** unless a rule names a loopback address (Windows Firewall ignores loopback too);
  otherwise "block app X" would also kill its DNS through the Privacy Shield proxy.
- **Fail-open.** A missing or invalid rules file keeps the last good table or allows everything at first start.
  Rejected rules are reported (`filter.rules` event) and shown on the Firewall page instead of being silent.
- **Daemon validation is looser than the filter in one spot**: `RuleSpecValidator` accepts short IPv4 forms
  like `1.2.3` (`IPAddress.TryParse`) that the filter rejects. Reported in the UI; validator not tightened.
- **DNS switching is done by the daemon**, not the app (no elevation prompt): `networksetup -setdnsservers`
  on active services, backup written before the change, restored on disable/uninstall/next start, upstreams
  re-discovered every 10 s. macOS cannot use a non-53 resolver port, so Privacy Shield only works on port 53.
- **DNS queries are usually attributed to `mDNSResponder`**, because apps resolve through it.
- **Keychain instead of DPAPI**: a random AES-GCM key in the login Keychain (SecItem API). With ad hoc
  signing every rebuild changes the identity; Developer ID avoids the prompts.
- **`Environment.UserInteractive` is always true on Unix**, `CommonApplicationData` is `/usr/share`. Never use
  them for service detection or data roots; use `AxiomPaths`.
- **Inbound socket-activated services** (sshd) are attributed to `/sbin/launchd` (pid 1).

Build, signing, distribution
- .NET parts publish on Linux (`scripts/macos/package-app.sh osx-x64|osx-arm64`); the Swift extension needs a
  Mac (Command Line Tools are enough, no Xcode). `package-app.sh --skip-publish --build-filter` on a Mac
  embeds, signs inside-out (Mach-O only) and produces `Axiom.app` and `Axiom.pkg` (pkgbuild, postinstall
  runs `axiomd --install-service`).
- Versioning contract: `AXIOM_VERSION` / `AXIOM_BUILD` are passed to the extension; the helper replaces the
  installed extension when version/build or cdhash differ; a release build fails without a version.
- **Development machines need SIP off + `systemextensionsctl developer on`** for ad hoc signed extensions.
  **Ad hoc rebuilds pin the NE filter config to the old cdhash**: the filter then reports "running" while
  allowing everything. Activation now resets the configuration on replace (one extra "Allow" prompt per dev
  upgrade). Developer ID builds should not hit this.
- **Release needs an Apple Developer Program team with the Network Extension capability** (self-serve in
  the portal per reports; unverified), Developer ID Application + Installer certificates, provisioning
  profiles for app and extension (app group becomes `<TEAMID>.com.axiom.firewall`), notarization. Env:
  `AXIOM_SIGN_IDENTITY`, `AXIOM_TEAM_ID`, `AXIOM_APP_PROFILE`, `AXIOM_INSTALLER_IDENTITY`.
- Recommended activation path for Developer ID is in-process via `libAxiomSysext.dylib` (entitlements live on
  the main executable); the `axiom-sysext` helper remains a fallback. The dylib path is proven ad hoc only.
- `publish -r osx-*` adds RID sections to `packages.lock.json`; they are reverted, not committed.

Layout on an installed Mac
```
/Applications/Axiom.app                                   user-owned bundle (app, dylib, helper, extension, service payload)
/Library/PrivilegedHelperTools/com.axiom.service/         root-owned copy of the daemon that launchd runs
/Library/LaunchDaemons/com.axiom.service.plist            KeepAlive {SuccessfulExit:false}, ThrottleInterval 10, AXIOM_SERVICE=1
/etc/newsyslog.d/com.axiom.service.conf                   log rotation (5 MB × 5)
/Library/Logs/Axiom/axiomd.log
/Library/Application Support/Axiom/                       0700; db, settings, DNS backup, network-recovery.txt 0600; filter/rules.json 0644
/var/run/axiom/axiom.sock (0666, auth by getpeereid)      /var/run/axiom/filter.sock (0600, filter → daemon)
~/Library/Application Support/Axiom/                      per-user UI settings, desktop.log
~/Library/LaunchAgents/com.axiom.firewall.agent.plist     autostart via `open -b com.axiom.firewall`
```

Useful commands: `axiomd --install-service | --uninstall-service | --doctor [--json] | --recover-network [--apply]`,
`axiom-sysext activate|deactivate|enable|disable|status [--force]`, `systemextensionsctl list`,
`log stream --predicate 'subsystem == "com.axiom.firewall.filter"'`.

## 3b. Linux implications (for the nft/eBPF port)

- `PeerAuthorization.Decide(uid, PeerPolicy)` and `IpcCommandAccess` (PublicRead / PrivateRead / Write) are pure and
  platform-neutral; the Linux branch moved `PeerAuthorization` to `Axiom.Infrastructure.Unix` and can take this policy
  unchanged (`SO_PEERCRED` instead of `getpeereid`). The dispatcher-level denial is shared code already.
- `FilterEnforcementState` (`Unavailable` / `Degraded` / `Pending` / `Verified`), the `filterEnforcement` report fields
  and `EffectiveRuleReport.EnforcementVerified` are in `Axiom.Contracts`: an nft adapter that applies synchronously can
  answer `Verified` from a readback of the live ruleset (`nft list ruleset`), while an adapter with a separate enforcement
  daemon should go through the same Pending → ack → Verified path. `RuleState` was not extended; `Pending` already exists.
- `MacLogPermissions` is only the policy (0700 dir, 0600 files); on Linux the equivalent is the journald/systemd
  `LogsDirectoryMode=0700` or the same helper against `/var/log/axiom`.
- Review #2 (MAC-1/MAC-2): "verified" means the **latest** report on the **current** connection is error-free for
  exactly the published generation, and each rule is proven against the table published for that generation (and
  the filter's `ruleIds` echo when present). A Linux adapter with a separate enforcement daemon must model the same
  latest-report record; an nft adapter proving by readback must re-read after every change rather than trusting an
  earlier success. Recovery-only removal must also wait for proof (ack or readback) and never stamp `VerifiedUtc` from
  the clock. The `filter.rules` NDJSON contract (moved to `Axiom.Infrastructure.Unix` on the Linux branch) gains the
  optional `ruleIds` field.

## 4. Not done / unverified

- Apple silicon: compiles (universal filter, osx-arm64 publish) but has never run. VM is Intel only.
- Developer ID signing, notarization, SIP-on activation: no Apple team available.
- macOS 13/14 code paths compile but were only executed on 15.
- IPv6/QUIC traffic, App Translocation, crash-relaunch of the extension: untested.
- Agent protection: config/hook locations (`~/.claude`, `~/.codex`, …) assumed equal to the Windows
  equivalents under `~`; not verified tool by tool. DKG/Blackbox guided installers are not available on macOS.
- No CI. Known flaky test under load: `HeadlessNavigationTests` (passes alone).
- Row context menus (upstream v0.13.0 "full context menus", and the older Remembered-decisions menu) do not open on a
  right-click in the VM, while the TextBox Cut/Copy/Paste flyout does; the toolbar buttons cover the same actions.
  Not investigated (QEMU tablet right button reaches Avalonia, so this is a ContextMenu-on-macOS issue, not input).
- Cosmetic: in the VM the application menu shows Avalonia's default menu instead of the custom NativeMenu
  (menu-bar icon menu works); AppleScript `quit` returns −128 although the app quits.
- Upstream: the shared-code changes are behaviour-neutral on Windows but touch 99 files. Suggested PR order:
  (1) `AxiomPaths` + `FirewallWriteGate` + `IpcRequestDispatcher`/seams + `PlatformText`/`AgentPlatform`,
  (2) `Axiom.Infrastructure.MacOS` + tests, (3) `Axiom.Service` dual-TFM, (4) `Axiom.Desktop.Avalonia.MacOS`,
  (5) UI fixes, (6) `macos/` + packaging.

## 5. Upstream merge v0.16.0 (`2a834c2`, merge `e07f112`)

Upstream since v0.13.2: 0.14.0 (Agent Protection/Activity above Network Control, compact KPIs, system status in the
page header), the manual macOS GitHub Actions workflow + its two test fixes, 0.15.0 (agent and network dashboards
split), `0e71bc1` (#288 #287 #277 #278), the 0.15.0 lock-file sync and 0.16.0 (Agent Health page, "Network
Dashboard").

Conflicts and decisions:

- `Infrastructure.Windows/Ipc/PipeServer.cs`: the port moved the request switch into the shared
  `Service.Hosting/Ipc/IpcRequestDispatcher.cs`; kept the delegation and replayed `0e71bc1` there
  (`rule.verify` is advertised in `capabilities` whenever a handler exists, outside the write gate; the Windows
  dispatch was already ungated). **`rule.verify` stays a `PrivateRead`** in `IpcCommandAccess`: it is read-only
  but the report carries rule/app paths and enforcement state, so a non-owner local user still gets
  `unauthorized` (the reflection test keeps every constant in exactly one set). Advertising ≠ authorizing.
- `UI.Avalonia/OverviewPageViewModel.cs`: took upstream's removal of `AgentActivity` (now on
  `AgentDashboardPageViewModel`); kept the port's `ProtectionActive` hook (review #25) so the header status follows
  SHIELD ON.
- `UI.Avalonia/SettingsPageViewModel.cs`: upstream's version-derived `ProductMilestone.Current` (`Axiom 0.16.0`)
  with the per-OS suffix (`· macOS port`; Windows `· Windows-first`, byte-identical). The capability report's
  `milestone` field now says `Axiom 0.16.0` on every platform (VM-verified); no other capability field changed.
- Upstream's CI fixes (TMPDIR=/tmp/axiom-ci for 104-char socket paths; link-free temp root in
  `ActivityFreshnessTests`) do not overlap the port's test helpers; both work.
- Lock files: upstream's synced versions taken; restore on Linux drops the `net10.0/win-x64` sections, so that churn
  was reverted and nothing lock-related is committed beyond upstream's.

Gate on the merged head (Linux host): `Axiom.sln` (EnableWindowsTargeting) 0 warnings / 0 errors,
`Axiom.Portable.slnx` 0/0; Infrastructure.MacOS 214/214, Desktop.Avalonia.MacOS 35/35, Presentation 93/93,
UI.Avalonia 43/43, Contracts 142/142, McpServer 33/33, Persistence 21/21. Core 117/128 and Service.Tests 67/79:
compared by failing test **name** with a pristine `origin/main` build on the same host: Core identical (11);
Service: main fails 12 of its 70, the branch 12 of 79 — the only difference is the port-added
`FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` (Windows `C:\` app path, same cause as
the coordinator tests main already fails; it was in the pre-merge failing set) on our side, and
`PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings` failing only on main
(not a regression on the branch). No new failures vs upstream.

VM smoke (macOS 15.8.3, SIP disabled, redeployed ad hoc): `capabilities` → `rule.verify` advertised, milestone
`Axiom 0.16.0`; `rules.query` → filter `verified`, connected, acked = published generation; `rule.apply` block
`/usr/bin/curl` → `applied` with `verifiedUtc` = ack time, `rule.verify` effectiveAction `block`,
enforcementVerified true, curl rc 7; `rule.remove` → curl HTTP 200, 0 rules. Screenshots:
`docs/screenshots/macos/{overview-agent-dashboard,network-dashboard,agent-health,firewall-network-control}-v0.16.0.png`.
Observed (upstream, not port): page-header subtitles are cut at 1280 px next to SYSTEM STATUS, and the Agent Health
button reads `Install/repair agent hooksâ€¦` (mojibake already in `origin/main` `AgentHealthView.axaml` and
`AgentsView.axaml`, shows on Windows too).
