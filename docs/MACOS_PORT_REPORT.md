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

## 6. Upstream merge v0.22.0 (`ecb6916`, merge `8941bdc`)

Upstream since `16229f4`: `f11893a` (Privacy Shield forwards allowed queries over RFC 8484 DoH), `4055827` (HaGeZi
TIF / phishing blocklists / public SHA-256 community feeds), `6838979` (Blackbox offline cached-ruleset continuity,
5-state reporting), `5c72c17` (hooked-agent status no longer depends on dashboard port 9700), `ceaa01c` (docs),
releases 0.18.0 to 0.22.0.

Conflicts (3 files, all `f11893a` against the portable DNS move) and decisions:

- `Service.Hosting/Dns/DnsProxyServer.cs` (upstream: `Infrastructure.Windows/Dns/DnsProxyServer.cs`): upstream's body
  as is (`DnsUpstreamTarget` list, `ForwardToTargetsAsync`, `ForwardDohAsync`, `ReadBoundedAsync`,
  `CreateDohHttpClient`, transport note in `Snapshot`). Port additions re-inserted: `IDnsAppAttributor` (last optional
  constructor parameter), the upstream failure streak, and the live swap, now `UpdateTargets(...)`; the DoH
  `HttpClient` is created when the first DoH target appears (constructor as upstream, or a later swap).
- `Infrastructure.Windows/Dns/SystemDnsResolver.cs`: the record, the known-DoH and bootstrap tables and the parsing
  members contain no Windows API, so they moved verbatim to `Service.Hosting/Dns/DnsUpstreamTarget.cs` and
  `DnsUpstream.cs`; `SystemDnsResolver` keeps `ResolveSystemDns` and forwards `TryParseUpstream`,
  `TryParseUpstreamTarget`, `UpgradeEndpoints`, `TryGetKnownDohUri`, `TryResolveBootstrapAddress`.
- `Service/PrivacyShieldController.cs`: upstream's selection, through the seam: explicit value →
  `DnsUpstream.TryParseTarget`; empty → `DnsUpstream.UpgradeEndpoints(_dns.DiscoverUpstreams())`; nothing found →
  1.1.1.1 + 8.8.8.8 upgraded to DoH with `IPrivacyDnsPlatform.NoUpstreamWarning` (Windows: upstream's 0.22.0 text).
  No new seam member was needed.

What DoH means on macOS: the DoH client is plain .NET (`HttpClient` / `SocketsHttpHandler`), nothing in it is
Windows-specific, so `axiomd` runs the same code. A system or configured resolver that is a known public resolver on
port 53 (Cloudflare, Google, Quad9, AdGuard) and an explicit `https://…/dns-query` URL are queried over HTTPS/443 with
no silent fallback to plain DNS; `udp://IP` and every other resolver (router, VPN, corporate) stay plain UDP/TCP.
The status `Detail` states the transport actually in use ("encrypted with DoH" / "prefer DoH; non-DoH upstreams remain
plain DNS" / "plain UDP/TCP DNS"), derived from the live target list, so nothing is claimed that is not active.
Upstream rediscovery (macOS only) upgrades the rediscovered endpoints the same way.

Known limit (upstream behaviour, same on Windows when the adapter points at the shield): a DoH URL whose host is
neither an IP literal nor in the built-in bootstrap table is resolved through the system resolver; while the shield
redirects system DNS to itself that lookup comes back to the proxy. Not changed here.

Found while merging: `6838979` probes the Blackbox guard at `venv\Scripts\python.exe` only, so on macOS/Linux an
installed guard read as "not installed" (`666f62f` red test, `0aea1d8` fix through `AgentPlatform.VenvPython`).
The version is 0.22.0 from `Directory.Build.props`; the Settings milestone still appends " · macOS port";
`package-app.sh` reads the version from the same file.

Not verified for this merge: DoH against a real resolver from `axiomd` on a Mac (covered here by the shared tests with
an injected HTTP handler on Linux only); the Windows service differential including Privacy Shield / DoH.

## Upstream `main` `e904bf8` (v0.68.0) merged (2026-11-16, merge `30cf0e3`)

Pinned `main` = `e904bf8a6c1615608cce5a121b0050f5988b6594` (v0.68.0). The range since the previous base `25bfcc1`
(v0.64.0) is 9 commits / 9 files: the agent command-guard rules (`src/Axiom.Contracts/Blackbox/AgentCommandGuard.cs`,
a Python helper string, plus its tests), release notes and the version bump. The merge had no conflicts. Nothing in
the range touches IPC, platform seams, file paths or Windows APIs, so no port change was needed.

Tested head: `30cf0e3` (the merge commit; this section is the only later change).

### Windows 11 VM (author-run, SDK 10.0.403, fresh `NUGET_PACKAGES` per tree)

| Check | `main` `e904bf8` | branch `30cf0e3` |
|---|---|---|
| `dotnet restore Axiom.Portable.slnx --locked-mode` | exit 0 | exit 0 |
| `dotnet restore Axiom.sln --locked-mode` | exit 0 | exit 0 |
| per-project `--locked-mode` restore | 21/21 PASS | 26/26 PASS |
| clean restore (`--no-http-cache`, empty package folder) | 88 packages | 88 packages |
| `dotnet build Axiom.sln -c Release` | 0 warnings / 0 errors | 0 warnings / 0 errors |

Lock files: all locked restores pass on Windows, so none was regenerated or committed. A `--force-evaluate` run on
Windows, kept out of the branch, changes only the in-repo project version ranges (`[0.54.0, )` -> `[0.68.0, )`);
pristine `main` drifts the same way. No package version, content hash or target-framework/RID section changes, and
no NuGet package version differs from `main`.

Windows suites (`dotnet test --no-build`, interactive scheduled task), failing tests by name versus `main`:

| Suite | `main` passed/total (failed) | branch passed/total (failed, skipped) | failing only on branch | failing only on `main` |
|---|---|---|---|---|
| Axiom.Contracts.Tests | 164/164 (0) | 173/173 (0) | none | none |
| Axiom.Core.Tests | 184/184 (0) | 184/184 (0) | none | none |
| Axiom.Infrastructure.Windows.Tests | 86/86 (0) | 154/154 (0) | none | none |
| Axiom.McpServer.Tests | 34/34 (0) | 34/34 (0) | none | none |
| Axiom.Persistence.Tests | 21/21 (0) | 21/21 (0) | none | none |
| Axiom.Presentation.Tests | 287/287 (0) | 307/310 (0, 3 skipped) | none | none |
| Axiom.Service.Tests | 101/101 (0) | 120/120 (0) | none | none |
| Axiom.UI.Avalonia.Tests | 62/62 (0) | 81/81 (0) | none | none |
| Axiom.UI.Tests | 194/198 (4) | 194/198 (4) | none | none |

On `main` and the branch the same 4 `AgentHookScriptTests` fail (no `python` on the VM). Branch tests skipped on Windows are the macOS-only ones (`MacBundleLayoutTests`, POSIX venv/provisioning gates); the Unix/Linux/macOS test projects are excluded from `dotnet test` on Windows by their `IsTestProject` condition. `WindowsFirewallPolicyAdapterTests` (known RCW flake) re-run 16 times per tree: 0/16 on the branch and on `main`.

### This host (Ubuntu, Release, `HOME`/`XDG_*` redirected to a scratch dir, `~/.hermes/config.yaml` SHA-256 unchanged)

| Suite | `main` passed/total (failed) | branch passed/total (failed, skipped) | failing only on branch | failing only on `main` |
|---|---|---|---|---|
| Axiom.Contracts.Tests | 164/164 (0) | 173/173 (0) | none | none |
| Axiom.Core.Tests | 170/184 (14) | 170/184 (14) | none | none |
| Axiom.Desktop.Avalonia.MacOS.Tests | not in tree | 35/35 (0) | none | none |
| Axiom.Infrastructure.MacOS.Tests | not in tree | 249/249 (0) | none | none |
| Axiom.McpServer.Tests | 34/34 (0) | 34/34 (0) | none | none |
| Axiom.Persistence.Tests | 21/21 (0) | 21/21 (0) | none | none |
| Axiom.Presentation.Tests | 280/287 (7) | 303/310 (7) | none | none |
| Axiom.Service.Tests | 86/101 (15) | 105/120 (15) | `FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` | `PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings` |
| Axiom.UI.Avalonia.Tests | 62/62 (0) | 81/81 (0) | none | none |

Builds: `Axiom.Portable.slnx`, `Axiom.Service` (`-p:EnableWindowsTargeting=true`), the port's desktop and test projects, Release: 0 warnings / 0 errors. Linux-side `--locked-mode` restore: both solutions and every project with a lock file give the same result as pristine `main`; on Linux `Axiom.Desktop` (NU1102 `System.CodeDom`) and `Axiom.Setup` (NU1004 RIDs) fail on `main` too (Windows-only WPF projects). The Service.Tests difference is the same as at the previous base: `FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` is a port test, `PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings` fails on `main` only on this host. The other Core/Presentation/Service failures on this host are Windows-only tests and fail identically on `main`.

Not tested in this round: the installed service/daemon (no runtime or service differential), Privacy Shield on
Windows, a second-user IPC run, packaging, anything on macOS itself (no macOS VM run at this head), including the status-bar refresh fix `e1bb085` (unit test only).

## Upstream `main` `3dde6b6` (v0.97.0) merged (2026-11-17, merge `ba68e2c`)

Pinned `main` = `3dde6b64c0010c46430351197ef576c3f1f8cc3a` (v0.97.0), 68 commits after the previous base `e904bf8`
(v0.68.0). One textual conflict, `src/Axiom.UI.Avalonia/MainWindow.axaml`: upstream's new header (Mini button, update
button after the bell, website link) is taken as is; the port keeps `x:Name="MinimizeButton"`, which the macOS
native-window-button code uses. The resolved file is identical to the Linux branch's resolution of the same range.

Tested code head: `32722a3`. Commits after the merge:

| Commit | Change | Origin |
|---|---|---|
| `2856037` | `EnforcementPolicyProvisioner` defaults and `EnforcementController` provisioning stay Windows-only (off Windows the defaults resolved to `/usr/share` and the caller's real home) | cherry-pick of Linux `645ca97` |
| `ce05ada` | host-shaped profile path in the default policy test | cherry-pick of Linux `9067a6c` |
| `ad56477` | vector update icon off Windows (upstream's button uses a Segoe MDL2 glyph) | cherry-pick of Linux `8b480da` |
| `50fb544` | drop that commit's call to `FitToWorkingArea()`, a Linux-branch-only helper that does not build here | macOS |
| `0c2fa6f` | header lamp truthful off Windows: neutral `UNKNOWN` lamp and "Protection: unknown" when the daemon does not answer (was: stale green, then red "Protection: off"); amber lamp plus "blocks not verified" while the shield is on but the filter has not verified the rules; Home `STATUS UNKNOWN`, Mini `Shield: unknown`. `ProtectionKnown` is always true on Windows and without a service, so Windows is unchanged | same intent as Linux `fe2bc08`, re-implemented (the macOS branch has no `ProtectionKnown` state) |
| `32722a3` | off Windows the protection probe feeds the shield state to Home, Mini and the lamp on every page, not only while Network Control is open | macOS (found by the new `ProtectionLampTests`) |

Port review of the range: no new IPC commands; no skip attributes in tests; every Windows `dotnet publish` of
`Axiom.Service` still passes `-f net10.0-windows`; the merge changed no lock file. Upstream's DeepSeek DSH
provisioning (`Axiom.Presentation/DeepSeekProtection.cs`) is referenced only by the Windows WPF UI. No macOS code
emits `OS_DENY_VERIFIED`. `BlackboxLocalState` still has a read-only `~/.hermes/blackbox` candidate; that predates
this range and is unchanged.

### This host (Ubuntu, Release, `HOME`/`XDG_*` redirected to a scratch dir, `~/.hermes/config.yaml` SHA-256 unchanged)

Locked restore (`--locked-mode`): `Axiom.Portable.slnx`, `Axiom.Service`, the macOS desktop project and both macOS
test projects exit 0 (pristine `main`: the solution and `Axiom.Service` exit 0). Windows-only lock sections cannot be
checked on this host. Builds (`-p:EnableWindowsTargeting=true`): 0 warnings / 0 errors on both trees.

| Suite | `main` passed/total | branch passed/total (skipped) | failing only on branch | failing only on `main` |
|---|---|---|---|---|
| Axiom.Contracts.Tests | 169/170 | 180/180 (0) | none | `EnforcementPolicyProvisionerTests.Default_policy_is_an_enabled_block_policy_for_every_harness` (Windows path shape; fixed by `ce05ada`) |
| Axiom.Core.Tests | 170/184 | 170/184 (0) | none | none |
| Axiom.Desktop.Avalonia.MacOS.Tests | not in tree | 35/35 (0) | none | none |
| Axiom.Infrastructure.MacOS.Tests | not in tree | 249/249 (0) | none | none |
| Axiom.McpServer.Tests | 34/34 | 34/34 (0) | none | none |
| Axiom.Persistence.Tests | 21/21 | 21/21 (0) | none | none |
| Axiom.Presentation.Tests | 285/292 | 308/315 (0) | none | none |
| Axiom.Service.Tests | 86/101 | 106/121 (0) | `FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` (port test, same as at the previous base) | `PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings` (same as at the previous base) |
| Axiom.UI.Avalonia.Tests | 64/64 | 84/84 (0) | none | none |

The other Core/Presentation/Service failures are Windows-only tests that fail identically on `main` on this host.

### macOS VM (author-run; Intel macOS 15.8.3 under OSX-KVM, SIP disabled, ad hoc signing)

Bundle 0.97.0 build 12 published on Linux, filter built and signed in the VM (`deploy-to-vm.sh`).

| Check | Result | Evidence |
|---|---|---|
| Active extension | PASS: `com.axiom.firewall.filter (0.97.0/12) [activated enabled]`; build 11 `[terminated waiting to uninstall on reboot]` | `systemextensionsctl list` |
| Daemon under launchd + `--doctor` (root) | PASS: `state = running`, 24 checks PASS, exit 0 | `axiomd --doctor` |
| Block through the filter | PASS: `rule.apply` block `/usr/bin/curl` -> curl rc 7 while `/usr/bin/python3` reaches the same `https://example.com` (200); `rule.verify` `enforcementVerified=true`, `effectiveAction=block` | IPC + curl/python |
| Survives `launchctl kickstart -k` | PASS: new generation acked, curl still rc 7, python 200, `rule.verify` verified | same |
| Unblock | PASS: `rule.remove` -> curl 200 | same |
| Tampered rules file (`chmod 664`) | PASS: `degraded`, filter `pending`, `rule.verify` `enforcementVerified=false`; `chmod 644` -> verified again | `sec-c-reject.py` |
| Privacy Shield on/off | PASS: on -> Ethernet DNS `127.0.0.1`, `doubleclick.net` gets no answer, `example.com` resolves; off -> "There aren't any DNS Servers set on Ethernet.", `example.com` resolves | `networksetup`, `dig` |
| Desktop app + new header | PASS: Mini/Simple/Advanced switch, bell; lamp green `SHIELD ON`, "blocks verified 00:00" | screenshot |
| Status-bar refresh `e1bb085` live | PASS: on Agent Dashboard, `rule.apply` over IPC -> "blocks verified 00:03" and "2 rule(s)" within 12 s; `chmod 664` -> amber lamp, "blocks not verified" | screenshots |
| Daemon stopped (`launchctl bootout`) | PASS: grey `UNKNOWN` lamp, "Protection: unknown · the local service did not answer", "IPC: service offline"; after `bootstrap` green again | screenshots |
| Privacy Overview, Mini | PASS: resolver page renders (DISABLED after the test; `dig` listed under blocked-by-application); Mini shows `Shield: ON` / `Privacy: OFF` | screenshots |

Not tested in this round: second-user IPC refusal; the Windows VM (locked restore of Windows lock sections, Windows
suites, Privacy Shield on Windows); the update button in its visible state (no update was offered); Developer ID
signing, notarization, SIP on and Apple silicon. The Agent Dashboard subtitle "Read-only inventory. No driver, no
firewall write" is upstream's static page text, not a protection status.

## Upstream `main` `da1987a` (v1.1.0) merged (2026-11-17, merge `d65b96d`)

Tested code head: `2cc62b4` (the VM bundle was published from `1f589fb`; `2cc62b4` changes tests only). Pin: `main` `da1987a1896275f0127eb8fe176c1a780471ebe9`. Author-run evidence on a project machine (Intel QEMU VM, SIP disabled, ad-hoc signing). This is not CI and not release evidence.

**Changes on top of the merge (shared code, behaviour-neutral on Windows).**
- `1f589fb` (from the Linux port's `13a7a94`): off Windows, `RuleSpecValidator` refuses drive-letter, backslash and UNC application paths with `rule.path.windows_style`; Windows unchanged. `AgentExecutables` splits on native separators only (upstream behaviour). Tests return early on the other OS; nothing is skipped.
- `2cc62b4` (from the Linux port's `d231e11`): import and coordinator tests use a native rule path per OS.
- Earlier in this round: `5384dbc` one shield level model in upstream's `EnforcementLevel` vocabulary (unknown is not green), `ea27fe9` filter acknowledgement is not `OS_DENY_VERIFIED`, `b76673a` DNS platform errors go through `IPrivacyDnsPlatform`.

**Host (Linux, Release, scratch HOME/XDG, agent config sha256 unchanged).** Locked restore passes for every port target; build 0 warnings / 0 errors (portable solution, service, macOS desktop host, macOS test projects). No skipped tests.

| suite | branch total/passed/failed | `main` da1987a |
|---|---|---|
| Contracts | 180/180/0 | 170/169/1 |
| Core | 190/186/4 | 184/170/14 |
| Persistence | 21/21/0 | 21/21/0 |
| McpServer | 34/34/0 | 34/34/0 |
| Presentation | 348/341/7 | 315/307/8 |
| UI.Avalonia | 90/90/0 | 66/65/1 |
| Service | 124/116/8 | 101/86/15 |
| Infrastructure.MacOS | 249/249/0 | n/a |
| Desktop.Avalonia.MacOS | 35/35/0 | n/a |

By name, no test fails on the branch that passes on `main`. All 19 branch failures fail on `main` too on this Linux host (Windows-only behaviour: UNC validation, Windows system binaries, provisioning, network recovery, agent canary). The tests that fail only on `main` here are Windows-path tests the port made OS-native, the default-policy test, `ShieldProcessFilterTests.Axiom_own_install_and_module_paths_are_never_prompted` and `PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings`.

**VM (macOS 15.8.3 24H241, x86_64, SIP disabled, build 1.1.0 (14), ad-hoc signed, TeamIdentifier not set).**
- App entitlements: content-filter-provider-systemextension, system-extension.install, app group `group.com.axiom.firewall`, cs.allow-jit / allow-unsigned-executable-memory / disable-library-validation. Extension: content-filter-provider-systemextension plus the app group. `codesign --verify --deep --strict` passes.
- `systemextensionsctl list`: `com.axiom.firewall.filter (1.1.0/14) [activated enabled]`; the old 0.97.0/12 copy is `terminated waiting to uninstall on reboot`.
- The daemon runs under launchd (`system/com.axiom.service`, running). `--doctor`: every check passes except one WARN for that old extension copy, which is waiting for a reboot (exit 1).
- Block test: `rule.apply` on `/usr/bin/curl` gives applied and verified. curl to example.com is refused (rc 7) while python3 gets HTTP 200 from the same host. `rule.verify` returns enforcementVerified true. After `launchctl kickstart -k` the rule is verified again, curl is still blocked and python is still at 200. `rule.remove` brings curl back to 200.
- Tampered rules file (`chmod 664`): the filter rejects it, the daemon reports `degraded` / pending, and `rule.verify` returns enforcementVerified false. Restoring the mode returns it to verified.
- Windows-style paths over IPC (`C:\...\curl.exe`, `\\server\share\x.exe`, `/usr/bin\curl`): each one is refused (`rule.invalid`) and no rule is stored.
- Privacy Shield on: DNS is set to 127.0.0.1, the blocked name returns no answer and example.com resolves. Off: DNS is back to automatic and example.com resolves.
- Second local user (temporary standard account, deleted afterwards): snapshot, history, diagnostics, rules.query, rule.verify, live.events, config.get and rule.apply are all refused as `unauthorized`. serviceHealth and capabilities answer. The install owner and root are allowed.
- Desktop app: the lamp is green "SHIELD ON / blocks verified" with the filter verified, amber "blocks not verified" with the filter degraded, and grey `UNKNOWN` ("Protection: unknown", IPC offline) while the daemon is stopped. The Privacy Dashboard renders, and Integrations does not offer Trader Shield. App RSS was 168 MB after 5 minutes, with the leftover 290 MB `~/.hermes/blackbox/ruleset.json` in place.

**Findings (not fixed in this round).**
- With the daemon stopped, the Network Control page body still shows the last-known "Axiom Shield ON" and "Filter: connected … verified". Only the status bar lamp turns UNKNOWN.
- The daemon itself (`/Library/PrivilegedHelperTools/com.axiom.service/axiomd`, DoH to 1.1.1.1/9.9.9.9) is listed as a new outbound application awaiting a decision. Axiom's own helper path is not in the never-prompt set on macOS.
- The status bar showed "1 rule(s)" while `rules.query` returned an empty list (the count probably includes the remembered curl Allow decision). Not investigated.

**Not tested in this round:** rule export/import through the app, Apple silicon, SIP enabled, Developer ID signing and notarization, upgrade from a signed build, Windows runtime suites.

**Artifact:** `Axiom-1.1.0-14-osx-x64-adhoc.zip` (the tested `/Applications/Axiom.app`, `ditto -c -k --keepParent`), 89,030,687 bytes, sha256 `124a8af8125bec4770ab7294729168dfb4f5be54c153a324467245550d93023a`. Ad-hoc signed, not notarized.

## Addendum 2026-11-18: UI truthfulness fixes, VM look (author-run, not CI, not release evidence)

Tested SHA `4229cb7` (fixes 63722e9, f8cfb50, 9111439, 026953e + Windows-regenerated lock files on top of the
v1.1.0 merge), build 1.1.0 (15). Intel VM (x86_64), macOS 15.8.3, SIP disabled (picker toggle, `csrutil status`:
disabled), app and filter ad-hoc signed (`Signature=adhoc`, `codesign --verify --deep --strict` ok), not
notarized. `Axiom.UI.Avalonia.dll` in the guest bundle has the same sha256 as the Linux publish output
(`e160abb4…253099`).

- Extension 1.1.0/15 activated enabled (1.1.0/14 terminated, waiting to uninstall on reboot); daemon running
  under launchd; `--doctor` 23 PASS / 1 WARN / 0 FAIL, the WARN being the old 14 copy, exit 1 for that WARN.
- Live block through the filter: rule on `/usr/bin/curl` applied and `rule.verify` enforcementVerified=true;
  curl to example.com refused 10/10 (rc 7) while python got HTTP 200 5/5 from the same host; after removal
  curl 200 5/5.
- Simple home: AI AGENT GUARD **NOT VERIFIED**, "Unsupported on macOS for now: Blackbox host hooks are not
  verified here, so AI agents are not protected".
- Network Control, verified rule: "Axiom Shield ON", "Filter: connected · generation … verified", footer
  "Protection: ON · 1 rule(s) · 1 awaiting decision", "blocks verified".
- Daemon stopped (`launchctl bootout`): "Axiom Shield UNKNOWN", "Protection status unknown: the local service did
  not answer.", no pending rows, filter section READ-ONLY / Unknown with no "verified" line, lamp UNKNOWN, footer
  "Protection: unknown · the local service did not answer". Still stale on that screen: the SYSTEM STATUS header
  kept "Protection active: Axiom rules apply; firewall writes enabled. No telemetry.", the "Disable protection"
  button stayed, and the owned-rules table kept the last read (curl "Applied") under an "unknown" note.
- About 10 s after `launchctl bootstrap`: back to Shield ON, filter verified (new generation), footer "1 rule(s)".
- New outbound applications after traffic (Privacy Shield on/off, so the daemon made its upstream DNS
  connections; python and nc to example.com): only "Python" (CommandLineTools Python.app) was listed, 1 pending.
  axiomd, Axiom.app and the filter extension were not listed.
- Rule removed: "Protection is on · 0 Axiom rule(s)", footer "Protection: ON · 0 rule(s) · 1 awaiting decision".
- Guest left with shield off, 0 rules, Privacy Shield disabled, DNS automatic; VM shut down.
- Artifact: `Axiom-1.1.0-15-osx-x64-adhoc.zip` (tested `/Applications/Axiom.app`, `ditto -c -k --keepParent`),
  89,036,424 bytes, sha256 `e932f0e69ee0a58a7167e4758a4ba34643465b81eb19cbb4c1fe251f69acce27`.

## Addendum 2026-11-18 (2): daemon-stopped UI fixes, VM look (author-run, not CI)

Tested SHA `3194639`, build 16 (`AXIOM_BUILD=16`), published on Linux, filter built and ad hoc signed in the
OSX-KVM guest (macOS 15.8.3, x86_64, SIP disabled at the OpenCore picker, `csrutil status` checked over ssh).
App and extension `Signature=adhoc`, flags `adhoc,runtime`, no Team ID, not notarized; `codesign --verify
--deep --strict` ok. Installed `Axiom.UI.Avalonia.dll` sha256 `a46ac63a…7be25` = Linux publish output.
Artifact: `Axiom-1.1.0-16-osx-x64-adhoc.zip` (tested `/Applications/Axiom.app`, `ditto -c -k --keepParent`),
89,032,774 bytes, sha256 `08715fc081b4a02de41f718ed849cc5b7dae7991166703c9bec2a8303ecfacb8`.

Smoke: launchd job running, `--doctor` 24 PASS / 0 WARN / 0 FAIL, `com.axiom.firewall.filter (1.1.0/16)
[activated enabled]`, filter verified. With Axiom Shield enabled (`protection.enable`, policy ask) and a block
rule on `/usr/bin/curl`: rule.verify enforcementVerified=true, curl 10/10 refused (rc=7) while python3 got 200
from the same host 5/5; after rule.remove curl 5/5 got 200. (Without the shield enabled, rule.apply answers
`not_supported`, "Firewall writes are disabled on this service.", as designed.)

GUI (1280x800), one applied verified rule. What the screen showed:
- Daemon up, Network Control: header "Protection active: Axiom rules apply; firewall writes enabled. No
  telemetry."; "Axiom Shield ON", "Disable protection"; filter SHIELD ON, "Filter: connected · generation …
  verified"; count 1, row curl "Applied"; footer "Protection: ON · 1 rule(s) · 1 awaiting decision", "blocks
  verified", lamp SHIELD ON. New outbound applications: only Python (axiomd, Axiom.app and the filter
  extension not listed). Simple home: SHIELD ACTIVE, FIREWALL SHIELD ON, AI AGENT GUARD NOT VERIFIED.
- Daemon stopped (launchctl bootout), Network Control 12 s later: header "Protection status unknown: the
  local service did not answer. Monitor unavailable: Service unavailable: The service did not respond in
  time. (service_unavailable)"; badge UNKNOWN, "Protection status unknown: the local service did not
  answer."; button "Check protection"; filter READ-ONLY, "Unknown / unknown"; "1 owned rule(s) shown as last
  known …", count "—", row curl "Unknown (last…"; footer "Protection: unknown · the local service did not
  answer", lamp UNKNOWN, "IPC: service offline". Matches.
- "Check protection" pressed while stopped: no dialog, screen unchanged. Matches.
- Back (launchctl bootstrap) 2 s: every surface unknown (header "Protection status unknown … The monitoring
  worker has not produced a snapshot yet.", page UNKNOWN, footer unknown, lamp UNKNOWN). 10 s: all verified
  together (header "Protection active …", page ON, footer "blocks verified", lamp SHIELD ON). Matches.
- Simple home stopped 12 s: "STATUS UNKNOWN · Protection status is unknown", tile FIREWALL SHIELD UNKNOWN,
  footer "Protection: unknown · the local service did not answer", lamp UNKNOWN.

Does not match (recorded, not patched):
- Desktop app crash: about 1 s after a `launchctl bootstrap` the app aborted with an unhandled
  `System.Net.Sockets.SocketException (13): Permission denied /var/run/axiom/axiom.sock` thrown from
  `AgentsPageViewModel.RefreshThreatShareAsync()` via an async event handler (`desktop.log` [fatal] entry;
  crash report EXC_CRASH SIGABRT). Seen once in two restarts with the app open.
- Simple home stopped 12 s: header says unknown but the button still reads "Turn Shield Off" (Linux shows
  "Check Firewall" in that state). 3 s after the stop Simple home still showed "SHIELD ACTIVE · Firewall
  Shield is protecting your apps", tile ON, footer "Monitoring: unavailable … Protection: ON · 1 rule(s)",
  lamp SHIELD ON.
- First return run, 2 s: header "Protection status unknown: the local service is offline." while the footer
  read "Protection: ON · 1 rule(s) · 1 awaiting decision · blocks not verified", amber SHIELD ON lamp,
  "IPC: service offline" (header and footer disagree; neither claims verified). 10 s: header "Protection
  active: Axiom rules not verified as enforced: the network filter has not connected …" and footer "blocks
  not verified" (agree); verified at about 13 s.
- Opening Network Control after the stop (no earlier read in that page) shows an empty table, count "—".
- In the stopped state the last-known row's Unblock button looks enabled (greyed on Linux); not pressed.
- Switching to Simple mode left the content area blank until Home was clicked in the side bar.

Guest left with shield off, 0 rules, Privacy Shield disabled, DNS automatic; VM shut down.

## Addendum 2026-11-18 (3): shared "service unreachable" signal and IPC connect-crash fix, VM look (author-run, not CI)

Tested SHA `eb3be61`, build 17 (`AXIOM_BUILD=17`), published on Linux, filter built and ad hoc signed in the
OSX-KVM guest (macOS 15.8.3, x86_64, SIP disabled at the OpenCore picker, `csrutil status` checked over ssh).
App and extension `Signature=adhoc`, flags `adhoc,runtime`, no Team ID, not notarized; `codesign --verify
--deep --strict` ok. Installed `Axiom.UI.Avalonia.dll` sha256 `52a34da0…ac70ec15` = Linux publish output.
Artifact: `Axiom-1.1.0-17-osx-x64-adhoc.zip` (tested `/Applications/Axiom.app`, `ditto -c -k --keepParent`),
89,035,425 bytes, sha256 `ed215027aac11350f8b6d497b9ba993230817d31e543c31498fc7c85cd3688c2`.

Smoke: launchd job running, `com.axiom.firewall.filter (1.1.0/17) [activated enabled]` (build 16 listed as
"terminated waiting to uninstall on reboot"), `--doctor` 23 PASS / 1 WARN / 0 FAIL (the WARN is that
build-16 entry), filter verified. Shield enabled, block rule on `/usr/bin/curl`: rule.verify
enforcementVerified=true, curl 10/10 refused (rc=7) while python3 got 200 from the same host 5/5; after
rule.remove curl 5/5 got 200.

GUI (1280x800), one applied verified rule; timed screenshots, offset = seconds after the
`launchctl bootout|bootstrap` ssh call returned (about 0.36 s round trip).

| Moment | Header | Page | Footer / lamp | |
|---|---|---|---|---|
| NC up | Protection active: Axiom rules apply | Shield ON | Protection: ON · 1 rule(s) / SHIELD ON | agree |
| NC stop +1, +2 s | Protection active | Shield ON | ON / SHIELD ON | agree (old state) |
| NC stop +3 … +10 s | Protection status unknown: the local service did not answer | UNKNOWN, Check protection, last-known row "Unknown (last…", Unblock greyed, count — | Protection: unknown · the local service did not answer / UNKNOWN, IPC: service offline | agree |
| NC start +1 s | unknown (monitoring worker has not produced a snapshot yet) | UNKNOWN | unknown / UNKNOWN | agree |
| NC start +2 … +5 s | Protection active: Axiom rules not verified as enforced: the network filter has not connected | Shield ON | ON · blocks not verified / SHIELD ON | agree |
| NC start +7, +10 s | Protection active: Axiom rules apply | Shield ON | ON, blocks verified / SHIELD ON | agree |
| Simple stop +1, +2 s | – | SHIELD ACTIVE, Turn Shield Off | ON / SHIELD ON | agree (old state) |
| Simple stop +3 … +10 s | – | STATUS UNKNOWN, Check Firewall | unknown / UNKNOWN | agree |
| Simple start +1 s | – | STATUS UNKNOWN · Protection status is unknown, "…the service has not reported the network filter's state", Check Firewall | Protection: ON · 1 awaiting decision · blocks not verified / amber SHIELD ON | DISAGREE (neither verified) |
| Simple start +2 … +5 s | – | NOT VERIFIED · Shield is on, blocking is not verified, Turn Shield Off | ON · blocks not verified | agree |
| Simple start +7, +10 s | – | SHIELD ACTIVE | ON / SHIELD ON | agree |
| Mini stop +1 s / +3 … +10 s | – | Shield: ON, Shield Protected / Shield: unknown, Shield Unknown | – | – |
| Mini start +1 / +2 / +5, +10 s | – | Shield: ON, Shield Degraded / Shield: unknown, Shield Unknown / Shield: ON, Protected | – | flicker |

Measured delay stop -> all unknown: between 2 and 3 s on Network Control, Simple home and Mini (all
surfaces in the same frame). No sampled frame showed one surface ON/verified while another said unknown.
Simple home and Network Control both reached verified between 5 and 7 s after the bootstrap.

- Network Control opened with the daemon down in a freshly launched app: "Axiom-owned rules could not be
  read: the local service did not answer. Whether any exist is unknown until it answers.", empty table,
  count "—", filter READ-ONLY "Service offline". Matches.
- Crash check: app open on Agent Protection, 10 `launchctl bootout`/`bootstrap` cycles about 4 s apart,
  then 5 more on Network Control: app pid 2282 unchanged throughout; `desktop.log` gained no lines (its one
  `[fatal]` is the 04:51:27Z build-16 crash); Axiom crash reports 6 user / 14 system before and after
  (no new report). The connect-time crash did not recur.

Not as expected (recorded, not patched):
- Simple home +1 s after bootstrap said STATUS UNKNOWN while the footer said "Protection: ON · blocks not
  verified" (one sample, see table).
- Mini +1 s after bootstrap "Shield: ON / Degraded", +2 s back to "Shield: unknown", +5 s Protected.
- "Check protection" while down was not pressed on macOS this round: the page had stayed scrolled and the
  click landed on page text. Earlier round: no dialog, nothing sent.

Guest left with shield off, 0 rules, Privacy Shield disabled, DNS automatic, no dialogs; VM shut down.

## Addendum 2026-11-18 (4): 1.3.0 build 18, macOS Intel Developer Preview 1 release-candidate run (author-run, not CI)

Tested commit `e2b74db4aca7957013119b5ae81a05a7f11a1276` (upstream v1.3.0 merged), `AXIOM_BUILD=18`. .NET parts
published on Linux (`package-app.sh osx-x64`, tree clean after), then copied into the OSX-KVM guest where
`deploy-to-vm.sh` with `INSTALL=0` ran `package-app.sh --skip-publish --build-filter` (Swift filter built, whole
bundle ad hoc signed). The signed bundle was packed in the guest with `ditto -c -k --keepParent` and copied to
the host: `Axiom-1.3.0-18-osx-x64-adhoc.zip`, 89,050,937 bytes, sha256
`89930957b595fb8e6a001815ab7b1783f6fb0ff8c1e82aae8cb97b55c976ffc6` (guest = host). The installed copy was
extracted from that same file (`shasum -c` OK in the guest), and its `Axiom.UI.Avalonia.dll` sha256 equals the
Linux publish output (`078b4035…5f2f`). Guest: macOS 15.8.3 (24H241), x86_64, SIP disabled, developer mode on.

Removal of build 17, as the release notes give it: `axiomd --uninstall-service` exit 0 (newsyslog file, helper
dir and launchd job removed); `axiom-sysext deactivate` over SSH exit 1 (`OSSystemExtensionErrorDomain` 13,
"authorization required (run from a GUI login session)"; the filter configuration was removed anyway); in the
GUI Terminal it asked for the admin password and returned `deactivated`, exit 0, extension 17 "terminated
waiting to uninstall on reboot"; `sudo rm -rf /Applications/Axiom.app` ok. Left behind:
`/Library/Application Support/Axiom` (db, filter/, network-recovery.txt, privacy and protection settings) and
`~/Library/Application Support/Axiom`.

By-hand install from the zip: `ditto -x -k` and `unzip` both propagated a simulated browser quarantine
(`xattr -w com.apple.quarantine`); launching the quarantined app from /Applications ran it translocated and
Gatekeeper refused it ("“Axiom” Not Opened", Done / Move to Trash). After `xattr -dr com.apple.quarantine` it
started from /Applications, `codesign --verify --deep --strict` still ok. `axiomd --install-service` exit 0;
`axiom-sysext activate` -> "would like to use a new network extension" -> Open System Settings -> toggle +
password -> `[activated enabled]`; a second `activate` (first one was cut by our 45 s alarm) enabled the
content filter -> "Would Like to Filter Network Content" -> Allow. The app's own "Install the Axiom background
service" dialog rendered with an empty dark body (buttons only).

| Check | Result |
|---|---|
| launchd / extension / codesign | running / `(1.3.0/18) [activated enabled]` / verify-ok, adhoc, no Team ID |
| `--doctor` | 24 PASS / 0 WARN / 0 FAIL, exit 0 |
| Block curl vs python, same host | run 1: refused 20/20 (rc 7), python 200 10/10; run 2: 4/4 refused |
| Daemon restart (`kickstart -k`) | run 1: 10/10 rc 7 right after; run 2: 14/14 rc 7 over 40 s, python 200 every probe, rule re-verified |
| Unblock | run 2: 12/12 HTTP 200 |
| Second standard user (axtest2, temporary) | 7 private reads + rule.apply `unauthorized`; serviceHealth, capabilities answered; user deleted after |
| Privacy Shield | on: DNS 127.0.0.1, doubleclick.net unresolved, example.com resolved; off: automatic on both services |
| `--recover-network` dry / `--apply` (daemon booted out) | exit 1 "Dry run: no change was made." / exit 0, adapters 2 verified, rules removed 0 |
| NC stop/start series | last state at +1 s, all unknown at +3 s; not verified at +3/+6 s after start, verified at +10 s |
| Local modules (Agent Protection) | "Start local modules": "Neither local module answered. Install or Repair each card, then try Start local modules again."; card button is "Install" (no Repair shown): "Guided module installation is not available on macOS yet. Install the module manually, then click Check again." |
| AI AGENT GUARD tile | NOT VERIFIED, "Unsupported on macOS for now: Blackbox host hooks are not verified here, so AI agents are not protected" |
| New-applications list | only Python; "12 trusted process(es) are not prompted (macOS system or Axiom's own)" |
| 10 bootout/bootstrap cycles on Agent Protection | app pid unchanged, desktop.log unchanged (no new [fatal]), no new crash report |

Failure / unexplained (not patched): in run 1, from about 3 s after the daemon restart, curl timed out (rc 28,
not the filter's rc 7) on 20/20 probes for about 2.5 min, including 10 probes after `rule.remove`, and a
`dscacheutil` lookup hung (20 s timeout, which ended the script); python got 200 5/5 early in that window. It
cleared by itself (curl 200 at 08:45:23Z) and the full repeat (run 2) was clean. Cause not determined.
Also: the "Start local modules" message points to a Repair button the macOS cards do not show.

Guest left with build 18 installed, service running, extension active, 0 rules, shield off, Privacy Shield
off, DNS automatic, no dialogs; VM shut down.

## Addendum 2026-11-18 (5): resolver-delegated DNS fix, 1.3.0 build 19, VM regression run (author-run, not CI)

Fix for the v13 outage found on build 18 (an app block rule dropped mDNSResponder's delegated DNS socket; lookups
of that name stalled for every app, 22 minutes in the repro). Fix commit `3943b54` (`RuleTable.decide` +
`ResolverDelegation`, `FlowInspector.socketOwner`, `FilterDataProvider.handleNewFlow`), design and trade-off in
MACOS_ARCHITECTURE.md "Resolver-delegated DNS flows". No .NET change (the new `flow.open` fields are additive).

Build: .NET published on Linux from `3943b54` (`AXIOM_BUILD=19 package-app.sh osx-x64`, tree clean after), Swift
filter built and the bundle ad hoc signed in the guest (`deploy-to-vm.sh`, `INSTALL=0`), packed there with
`ditto -c -k --keepParent`: `Axiom-1.3.0-19-osx-x64-adhoc.zip`, 89,058,431 bytes, sha256
`74568194086be232e1fffbd0eaf1e92575f2cf78c741e653d41be34170f0efd9` (guest = host). Installed over build 18 from that
zip (`shasum -c` OK), `axiomd --install-service` exit 0, `axiom-sysext activate` replaced 18 with 19 and re-created
the filter configuration ("Would Like to Filter Network Content" -> Allow). Guest macOS 15.8.3, SIP disabled.

| Check | Result |
|---|---|
| Swift unit tests (guest, `build.sh test`) | RED with `decide()` stubbed to the build-18 verdict: 162/168 (6 failures, all delegated-flow cases); GREEN 168/168 |
| Loop 1, 10 min, right after the 18 -> 19 filter upgrade (rule on a curl copy; every second the copy fetches http://NAME/ first, then system curl and python fetch the same NAME; NAME alternates a never-seen sslip.io name and 5 real names; no cache flush) | 480 ticks. Filter: 511 `allow resolver-delegated dns` lines for the copy, **0** DNS drops, 1078 blocks of its TCP flows. Copy rc 7 454, rc 28 26; system curl 478/480; python 480/480. mDNSResponder `Broken pipe` 582 lines, but they started at the filter upgrade (590 in the 10 min before the loop) and also appeared with **no rule at all** (about 50 per 20 lookups in 6 controlled phases, system curl included). A DNS configuration change (Ethernet DNS set and reset to automatic) cleared them: 0 afterwards. Reading: replacing the filter left mDNSResponder with a broken socket (upgrade side effect, not a verdict) |
| Loop 2, 10 min after that reset, same script | 415 ticks. **0 `Broken pipe`**, **0 DNS drops**, 447 delegated DNS flows allowed, 920 TCP blocks of the copy. Real names (207 ticks): copy refused (rc 7) 207/207, system curl 207/207, python 207/207, 0 stalls. Fresh sslip.io names (208): copy rc 7 174, rc 28 (5 s lookup) 34; system curl 203/208; python 208/208 (6 lookups > 2 s, max 15.6 s) |
| Loop 3, 5 min, same script, **no rule** (control) | fresh sslip.io names: first asker timed out 6/128, system curl 127/128, 3 python lookups > 2 s; real names: 1/127 timeout. 0 `Broken pipe` |
| Build 18 for comparison (v13-outage FINDINGS) | one delegated DNS drop -> `Broken pipe` on every resend, query #1-#120 for one question, hostname lookups of the same name stalled for **all** apps for 22 min (23/25 + 5/5 restart cycles with timeouts) |
| Blocked program's own direct DNS | `dig` copy UDP rc 9 "connection timed out" (2.1 s), TCP rc 9 "connection ... failed"; `nslookup` copy rc 1 timed out; unblocked `dig`/`nslookup` answered. Filter: `block pid=… digblk -> 10.0.2.3:53 rule=… owner=-` (3 lines), 0 delegated allows for them |
| Enforcement smoke | copy refused by IP 5/5 and by name 5/5 (rc 7), python 200 3/3, `/usr/bin/curl` 0 3/3; same after `launchctl kickstart -k` (new pid); after `rule.remove` copy 200 3/3; `--doctor` 23 PASS / 1 WARN / 0 FAIL (WARN: build-18 extension "terminated waiting to uninstall on reboot"); `codesign --verify --deep --strict` ok, adhoc |
| UI (Light mode) | (a) "Install the Axiom background service" (menu-bar item "Install Background Service…", plist moved aside): body readable, dark on light; "Unblock this application" confirmation readable too. (b) Agent Protection, Start local modules: "Neither local module answered. The modules have to be installed and started manually; then click Check again." (no Repair; the static LOCAL MODULES subtitle still says "Repair stops a stale or duplicated runtime before starting a clean one."). (c) rule created over IPC (`createdBy b19-ipc`), row Unblock -> "curlblk: unblocked (rule removed and no longer listed; allow decision recorded).", row gone, 0 owned rules, copy then got 200 |

Not met / open: the fresh-name loops did not give "refused every time, never a timeout": 34/208 first lookups of
never-seen sslip.io names took 5 s with the rule vs 6/128 without it in a later 5-minute control. No filter drop,
no `Broken pipe` and no cross-app stall accompanied them, and earlier 20-name phases showed 10-20 % slow fresh
lookups with no rule, so this reads as upstream (sslip.io/slirp) latency, but the rule/no-rule difference was not
explained in this run. Also open: a filter upgrade can leave mDNSResponder with an EPIPE socket until the next DNS
configuration change. Not tested: Apple silicon, a signed build, macOS 13/14, DoT (853) live.
