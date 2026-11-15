# Axiom â€” historical change log

This is the original feature-by-feature release history extracted from the long README. Entries describe the version **at the time of release**, and earlier claims may have been corrected or superseded in later versions. For current architecture, safety and privacy behaviour see [Architecture](ARCHITECTURE.md), [Security model](SECURITY_MODEL.md), [Threat intelligence](THREAT_INTELLIGENCE.md) and [Privacy Shield](PRIVACY_SHIELD.md). Per-release build/test evidence is in [RELEASES](RELEASES/).

## What's in 0.33.0

- **Guard hardening from the attack-vector sweep (0.30.0/0.32.0 lab tests).**
  - Protected-path checks normalize shell variables (`C:\Users\llm`, `%USERPROFILE%`, `%APPDATA%`, `~`) and strip `\\?\`/`//?/`/`\\.\` prefixes; hidden-path reads are blocked.
  - `move`/`rename` and ownership/ACL changes (`takeown`, `icacls`, `attrib`, `Set-Acl`) on protected paths are blocked.
  - Extra upload shapes (`--data-binary`, `-T`, `--post-file`, Python `requests.post`) count as exfiltration of a protected file.

## What's in 0.32.0

- **Clearer Community feed vs. VirusTotal (`VT Check`) feedback in Integrations.**
  - Renamed the per-file row action button from `Check` to `VT Check` (with explanatory tooltip) and the context menu item to `Check hash on VirusTotal`, and initialized hashed rows to `VT: Not checked` (`Skipped` for unhashed entries) in `SecurityView.axaml` and `SecurityPageViewModel.cs`.
  - `ScanFilesAsync` now awaits any in-flight or unpopulated configured Community feed before comparing scanned SHA-256 hashes, and `ApplyCommunityMatches` surfaces an explicit neutral notice (`HasScanCommunityNotice`) even when 0 matches occur so users can see how many community hashes were checked locally.
  - Entering a VirusTotal API key from `VT Check` immediately runs the hash lookup on that row instead of requiring a second click, and `CreateReputationModule` reflects `IsConnected = true` when configured.

## What's in 0.31.0

- **Reliable row-click selection and container-preserving refreshes across all tabs.**
  - Styled `ListBox.data-list > ListBoxItem` and its template `ContentPresenter` with `Background="Transparent"`, `HorizontalContentAlignment="Stretch"`, and zero item-gap dead zones in `AxiomControls.axaml`, plus `DataListSelection.SelectOnPointerPress="True"` on the style and left-click focus handling in `DataListSelection.cs`.
  - Replaced `AxiomSelectableTextBlock` table cells with `TextBlock` and added `Background="Transparent"` on row templates across `ConnectionsView`, `EventsView`, `AppsView`, `OverviewView`, `AgentsView`, `AiAnalystView`, and `FirewallView` (preserving copy context menus and selectable detail panes).
  - Added `DataListSelection.SharedSelectedItem` for grouped `ListBox` views (`ConnectionsView`, `EventsView`) so multiple app groups share one ViewModel selection without sibling groups clearing it to `null`.
  - Added `CollectionSync.SyncInPlace` across `AgentsPageViewModel`, `ConnectionsPageViewModel`, `ConnectionAppGroup`, and `EventsPageViewModel` (and fixed `OnSelectedActivityChanged` when `HasSelectedActivity` is false plus `SelectedEvent` preservation in `EventsPageViewModel`) so background polls no longer destroy row containers mid-click.
- **Smaller `Axiom-Setup.exe` (`~149.7 MB` -> `91.0 MB`).**
  - Moved `UpgradeDataGuard` to `Axiom.Contracts.Blackbox`, decoupled `Axiom.Setup` from `Axiom.UI` and WPF (`UseWPF=true`), and replaced the WPF window with a DPI-aware dark-mode Win32 UI (`SetupNativeWindow.cs` + `app.manifest`).
  - Compressed the embedded Desktop/Service payload and community feed into a single `Axiom.Setup.Payload.zip` resource in `scripts/publish-setup.ps1` (extracted in `SetupInstaller.cs`) and enabled partial IL trimming (`PublishTrimmed=true`).

## What's in 0.30.0

- **One DKG home and an identity assertion (#307).**
  - Moved `DkgHomeResolver` to `Axiom.Contracts` so Setup, the desktop and the tests agree on the candidate homes, the `api.port` and the token line the node writes under a comment.
  - Setup now starts the CLI/home the Hermes config names instead of initializing a second home, and `UpgradeDataGuard` backs up every candidate DKG home.
  - New `DkgIdentityProbe` calls `GET /api/agent/identity` with the resolved home's own port and token; a 401 is reported as a home/token mismatch instead of a connected node.

## What's in 0.29.0

- **Single Trader Shield location in UI.**
  - Removed the duplicate `TraderShieldSectionView` from the Integrations view (`SecurityView.axaml`), keeping Trader Shield exclusively under Agent Protection (`AgentsView.axaml`).
  - Added headless Avalonia regression test `Trader_shield_appears_only_on_agent_protection_and_not_on_integrations` in `TraderShieldSectionViewModelTests`.
- **Smaller single-file service binary and portable release archive.**
  - Enabled `EnableCompressionInSingleFile=true`, `DebugSymbols=false`, and `AllowedReferenceRelatedFileExtensions=none` when publishing `Axiom.Service.exe` in `scripts/publish-setup.ps1` and `scripts/build-release.ps1` (`76.74 MB` -> `38.59 MB`).
  - Removed the redundant embedded `Axiom-Setup.exe` from `Axiom-<version>-win-x64.zip` and added `-ReusePayload` to avoid double-publishing Desktop and Service (`210.52 MB` -> `78.22 MB` portable ZIP).

## What's in 0.28.0

- **Firewall host-mask normalization on WFP/firewall readback (#282).**
  - Normalized IPv4 `/32` and IPv6 `/128` CIDR suffixes in `FirewallPolicy` / `NetshFirewallRuleManager` readback verification so bare host scopes verify and apply reliably without `rule.verify_failed`.
- **Single-instance mutex enforcement before Avalonia dispatcher startup (#283).**
  - Enforced the single-instance check in `Program.cs` before `BuildAvaloniaApp().StartWithClassicDesktopLifetime` so launching a second `Axiom.Desktop` instance exits cleanly with a user-friendly dialog instead of throwing an unhandled Avalonia Dispatcher exception.
- **Privacy Shield `Phishing` category, 8-source toggles, and Setup/service auto-DNS reliability.**
  - Added `PrivacyCategory.Phishing`, included it in `Strict`, reclassified `phishing-filter` (`Phishing`) and `hagezi-tif` (`Malware | Phishing`), prioritized `Malware | Phishing` downloads in `PrivacyShieldSourceUpdater`, and added `Phishing` category checkboxes to both Avalonia and WPF Privacy Shield views.
  - Optimized `PrivacyShieldPolicy.NormalizeDomain` with thread-static `IdnMapping` and ASCII fast-path scanning for ~700k+ rule rebuilds.
  - Increased `PrivacyConfigure` IPC timeout (`5s -> 60s`) and `PrivacySourcesUpdate` timeout (`3m -> 5m`), added `Mode=TwoWay` binding for source toggles, surfaced a warning if an older running service drops unknown source IDs, and woke `PrivacyShieldWorker` immediately after `ConfigureAsync`.
  - Updated `PrivacyDnsFailSafe.BuildFallbackCandidates` and `SelectTargetAdapter` (filtering loopback/site-local entries, falling back through saved -> current -> gateway/DHCP IPv4, preferring physical adapters over virtual ones, 45s PS timeout with kill), added a 30s reconciliation loop in `PrivacyShieldWorker`, registered `Axiom.Service.exe` early during Complete setup, and preserved existing user `privacy-shield.json` across desktop restarts.

## What's in 0.27.0

- **Reliable row selection, right-click copy, and refresh preservation in Agent Activity, Findings & Hook Evidence (#296).**
  - Replaced cell-level `AxiomSelectableTextBlock` inside `ListBox` row templates in `AgentDashboardView.axaml` and `AgentStatsView.axaml` with `TextBlock` (keeping `AxiomSelectableTextBlock` in the right-hand details panes), added `Background="Transparent"` on row grids, and wired `DataListSelection.SelectOnPointerPress` plus fixed `MainWindow.SelectContainingListItem` to walk visual ancestors past the `ItemsPresenter`/`VirtualizingStackPanel` container to the owning `ListBox`.
  - Passed `PlacementTarget.DataContext` as `CommandParameter` from row context menus (`Copy event`, `Copy details`, `Copy raw event JSON`, `Copy finding`, `Copy hook evidence`) and updated `AgentsPageViewModel` copy commands so actions always target the right-clicked row and keep selection and details panes in sync.
  - Guarded `ApplyFindings` with `_preservingFindingSelection` and `ApplyHookEvidence` with change detection and identity preservation so periodic background refreshes never drop or flash the user's selected row.
  - Added headless UI and ViewModel regression tests in `AgentActivitySelectionTests` using a single dedicated Avalonia UI thread (`TestAppBuilder.RunOnUiThread`).
- **Complete UTF-8 / cp1252 / CP437 mojibake cleanup & regression test (#299).**
  - Fixed all corrupted punctuation across `AgentHealthView.axaml` (`hooksâ€¦`), `AgentsView.axaml` (`â€”`), `AgentDashboardView.axaml` (`Â·`), `BlackboxDashboardClient.cs` (`â€”`), both `OpenCodeProtection.cs` guard scripts (`â€¦`), `README.md`, `docs/CHANGELOG.md`, and `docs/RELEASES/0.26.0.md`.
  - Added `SourceEncodingRegressionTests` to fail builds if any `*.cs`, `*.axaml`, or `*.xaml` source file under `src/` reintroduces mojibake sequences.

## What's in 0.26.0

- **Guard bridge under the committed interpreter.** The bridge re-execs the interpreter that matches the committed dependency environment before reading stdin, removing the per-call pydantic_core/
o tui_gateway warnings and letting the seed-phrase and keystore detectors load.

## What's in 0.25.0

- **Trader Shield UI, Wallet/Address Persistence & BIP-39 Seed-Phrase Runtime Repair (#320, #324).**
  - Added `BlackboxWordlistNormalizer` to repair Windows CRLF line endings back to LF (`2f5eed53â€¦`) across all installed Blackbox wordlist locations (`agent-blackbox`, `%LOCALAPPDATA%\hermes`, and `~/.hermes`) during install, startup provisioning, dashboard start, and Trader Shield self-test so seed-phrase detection stays active without requiring reinstallation.
  - Added `AgentProtectionSelfTest.TraderShieldChecks()` (synthetic non-uniform labelled BIP-39 seed-phrase write -> `secret:seed-phrase` block and Exodus keystore read -> `fileaccess:read_file:crypto-wallet` block), fixed `AgentProtectionSelfTest.Identifier` regex for underscore tool names and `secret:*` identifiers, and extended `TraderShieldProvisioner` with `Read` / wallet selection persistence across all 11 supported wallets.
  - Added `TraderShieldSectionViewModel` and `TraderShieldSectionView` (enable toggle, 11 wallet checkboxes, local-only validated `0x...` EVM address list, Save button, and live self-test button) embedded on both the Security (Integrations) and Agents views.

## What's in 0.24.0

- **Default ISP-blind encrypted DoH (`443`) for Complete install & auto-upstream mode.** Added `EncryptDnsViaDoh` (default `true`) on `PrivacyShieldSettings` and `PrivacyShieldPolicy.DefaultDohUpstream` (`"1.1.1.1, 9.9.9.9"`), added multi-target `SystemDnsResolver.TryParseUpstreamTargets` and `DefaultDohTargets()`, updated `PrivacyShieldController.TryCreateServer` so empty/automatic `UpstreamDns` never silently forwards plain UDP port `53` queries to a LAN router or ISP DNS when DoH encryption is enabled, defaulted Complete setup (`SetupDefaults` and `PrivacyShieldProvisioner`) to `"1.1.1.1, 9.9.9.9"` over HTTPS/2 TLS port `443`, and exposed the `Encrypt upstream DNS via DoH` toggle in both Avalonia and WPF Privacy Shield views.

## What's in 0.23.3

- **All 8 Privacy Shield blocklists enabled without rule truncation or IPC timeouts.** Raised `PrivacyShieldPolicy.MaxRules` from `500,000` to `1,000,000` and `SourceReserve` to `25,000`, prioritized `PrivacyCategory.Malware` feeds (`hagezi-tif`, `phishing-filter`, `urlhaus-domains`) in `PrivacyShieldSourceUpdater`, and increased the UI/provisioning `PrivacySourcesUpdate` IPC timeout from 5 seconds to 3 minutes so `HaGeZi Threat Intelligence Feeds Mini` and `Phishing domains` update cleanly alongside bulk lists.
- **24-hour automatic Privacy Shield blocklist updates.** Added `AutoUpdateSources` (default `true`, toggleable in the Privacy Shield view) and `AutoUpdateIntervalHours` (`24`) to `PrivacyShieldSettings`, plus background startup catch-up and hourly checks in `PrivacyShieldWorker` via `PrivacyShieldController.ShouldAutoUpdateSources`.
- **Seamless persistent adapter DNS across restarts and version upgrades.** Added `PreferredAdapterAlias` and `AutoPointAdapterDns` to `PrivacyShieldSettings`, `PrivacyDnsFailSafe.EnsureAdapterPointed` (LocalSystem, zero UAC), `PrivacyShieldController.EnsureConfiguredAdapterDns`, and automatic Complete-setup activation (`AutoPointAdapterDns = true`).
- **Cleaner DNS resolver statistics & faster upstream failover.** Excluded deprecated Windows IPv6 site-local dummy addresses (`fec0:0:0:ffff::1/2/3`) in `SystemDnsResolver.FilterSystemDnsAddresses`, tuned multi-target failover timeout to `1,500 ms` in `DnsProxyServer`, and avoided counting benign pre-query TCP disconnects as resolver errors.

## What's in 0.23.2

- **Wildcard protected directories in shell deletes.** The delete check no longer derives an empty stem from ~/.ssh/*; it uses the same path tokens as launch and upload, so del ~/.ssh/id_rsa blocks.

## What's in 0.23.1

- **Silent module & background execution for DKG / Blackbox.** Added `AxiomModuleProcessMatcher`, expanded `ModuleWindowHider` (WMI + `EnumWindows` fallback and `BackgroundWindowSettingsStore.Enabled` gating), added `"hermes"`, `"git"`, and `"pip"` to `BackgroundWindowHider.Names` across Presentation/UI/Desktop startup, switched `OptionalModuleInstaller.RunPowerShellScript` to `UseShellExecute = false` / `CreateNoWindow = true` with `pythonw.exe` dashboard preference and `$env:BLACKBOX_MODE = 'block'` / `$env:BLACKBOX_ATTACH_ALL = '1'`, added clean Antigravity/dashboard teardown in `OptionalModuleUninstaller`, and added automatic Blackbox launch & polling on `SecurityPageViewModel.RefreshAsync`.
- **Complete (`Full`) setup provisioning.** Added `Axiom.UI.Services.AntigravityProtection`, wired `AntigravityProtection`, `ZCodeProtection`, and `DeepSeekProtection` into `SetupInstaller` and `Axiom.UI.Services.AgentHookMaintenance` so all 11 supported AI agent harnesses are hooked automatically, and updated `SetupDefaults` and `PrivacyShieldProvisioner` to provision `PrivacyShieldProfile.Strict` (all 6 categories plus `Custom`, all 8 `PrivacyShieldSourceCatalog.All` blocklist sources) and `CommunityFeedCatalog.RecommendedBundleUrl` with `autoSync = true`.

## What's in 0.23.0

- **Complete install protected out of the box.** First start writes `mode: block`, provisions every agent hook, applies the Trader Shield for eleven wallets and `plugins.load_timeout_seconds: 120`, and runs a self-test that proves a protected read and write are blocked.
- **Full action-chain guard for agents.** The OpenCode bridge now blocks protected-path deletes, guard tampering, remote script pipes, encoded PowerShell, LOLBin downloads, persistence shapes, launching a protected file and uploading one, and quarantines a session after a high-severity prompt injection.
- **Reputation-safe threat sharing.** A local preflight refuses missing consent/key, non-vocabulary values, known indicators, canaries, EICAR, tracking and shared-hosting hosts; the reporter runs through the committed interpreter with two fallbacks.
- **Upgrade data guard and installer reliability.** Findings, history, the reporter key and the DKG identity are backed up before the vendor installer and restored if lost; the setup waits for a stopping service, retries locked files and reports silent failures.
- **BIP-39 wordlist normalized to LF.** Windows seed-phrase detection is restored by matching the vendor's pinned SHA-256.
- **Offline continuity from 0.22.0.** Guard availability, cached rules, stale sync, DKG offline and unprotected are reported separately, and the dashboard port no longer decides whether an agent is protected.

## What's in 0.22.0

- **Agent Blackbox Offline Runtime Continuity & 5-State Reporting (#324).** Added `BlackboxContinuityReport` (`GUARD_AVAILABLE`, `RULESET_AVAILABLE`, `SYNC_STALE`, `DKG_OFFLINE`, `UNPROTECTED`), preserved cached `ruleset.json` across offline periods/reboots in `TryReadSync` and `TryReadGraph`, and explicitly flagged corrupted/missing rulesets as `unavailable`.
- **Dashboard Port `9700` Decoupled from Hook Status.** Updated `SecurityPageViewModel` and `SecurityViewModel` to check local guard + `ruleset.json` continuity when the Blackbox dashboard port (`9700`) is stopped.
- **Offline Continuity Audit & Upstream RFC.** Added `docs/OFFLINE_CONTINUITY_AUDIT.md` covering upstream detector dependencies, offline test matrix results, and proposals for `verified_lookup_fallback: "index"` and Windows `bip39_english.txt` LF hashing.

## What's in 0.21.0

- **Encrypted RFC 8484 DNS-over-HTTPS (DoH) Upstream.** Privacy Shield now upgrades public upstream resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `94.140.14.14`, etc.) and explicit `https://.../dns-query` URLs to encrypted HTTP/2 DoH on port `443` with no silent plaintext downgrade.
- **Expanded Malware/Phishing Blocklists & Public SHA-256 Community Feeds.** Expanded `PrivacyShieldSourceCatalog` from 6 to 8 sources (`hagezi-tif`, `phishing-filter`) and upgraded `CommunityFeedClient` with plain-text SHA-256 parsing, multi-URL deduplication, and `CommunityFeedCatalog.Presets`.

## What's in 0.20.0

- **Stage E4 Scoped Agent Firewall Enforcer & Stage E3 Trusted File Broker (#323).** Added scoped per-agent Windows Firewall enforcement with rollback and dual-destination canary checks, plus the `TrustedFileBroker` prototype and ADR 0012.
- **Offline `DkgContextAnnotator`, Umanitek Upstream RFC & Enforcement Tracker (#231, #324).** Added read-only cached DKG indicator context annotations, upstream collaboration RFC, and roadmap tracking.

## What's in 0.19.0

- **Stage E1-to-E2 Host Enforcement Bridge & `EnforcementReceiptV1` (#322).** Added hash-chained enforcement receipts, strict `CommunityOnly` advisory gating, `HostEnforcementAdapter`, `EnforcementController` IPC endpoints, E2B bridge spec, and honest UI labels distinguishing guard flags from verified blocking.

## What's in 0.18.0

- **Reputation-safe Threat Share & anti-rejection pipeline (#321).** Added `ThreatShareModels`, AI process evidence provenance, DNS-to-process correlation, pre-flight novelty simulation CLI, and retract lifecycle so speculative reports never degrade reporter reputation.
- **Curator-signed RAM snapshot endpoint & opt-in LAN cache.** Added `VerifiedGraphPeerRelay` for signed verified-graph snapshot caching on opt-in local peers.

## What's in 0.17.0

- **Agent Health now carries the health surfaces.** Protected workspaces, **Blackbox health** and
  **Module health** live on the same page, in that order, instead of being split between Agent
  Protection and a separate page. The page shares `AgentsPageViewModel` and
  `SecurityPageViewModel`, so the probes, health samples and timers stay single-owner.
- **Agent Health page (introduced in 0.16.0).** Protected workspaces moved out of Agent Protection
  into a page directly below Agent Activity.
- **Network Dashboard rename (0.16.0).** The network page is now **Network Dashboard**, matching
  **Agent Dashboard**.
- **Network Events write gating (0.16.0, #288).** Block outbound/Block inbound are disabled when the
  service cannot apply firewall changes, with the reason shown and a result row that survives the
  10-second refresh.
- **Accurate empty states (0.16.0, #287).** No search matches no longer claims the service is down.
- **Read-only `rule.verify` (0.16.0, #277).** `rule.verify` is advertised even when writes are
  disabled; only `rule.apply` and `rule.remove` require the write capability.
- **Version-derived milestone (0.16.0, #278).** The FND-005 label follows the product version.
- **Verification.** `Axiom.UI.Avalonia` builds with 0 warnings and 0 errors; its suite passes 37/37,
  including headless navigation through all 14 pages.

## What's in 0.16.0

- **Agent Health page.** Protected workspaces moved out of Agent Protection into a dedicated page
  directly below Agent Activity. It reuses `SecurityPageViewModel`, so the protected-agent probes
  and their timers are not duplicated.
- **Network Dashboard.** The network page is now **Network Dashboard**, matching **Agent Dashboard**.
- **Network Events honours read-only mode.** Block outbound/Block inbound are disabled when the
  service cannot apply firewall changes, with the reason shown next to them; the action result row
  survives the 10-second refresh (#288).
- **Accurate empty states.** A search with no matches no longer claims the service is stopped (#287).
- **Read-only `rule.verify`.** The service advertises `rule.verify` even when writes are disabled;
  only `rule.apply` and `rule.remove` depend on the write capability (#277).
- **Version-derived milestone.** The FND-005 label now follows the product version (#278).
- **Verification.** `Axiom.UI.Avalonia` builds with 0 warnings and 0 errors; its suite passes 37/37,
  including headless navigation through all 14 pages.

## What's in 0.15.0

- **Agent and Network dashboards are separate.** The default landing page is now **Agent
  Dashboard**: sessions, tool calls, blocked and flagged counts plus the agent activity table and
  security findings. **Network** keeps sockets, processes, loopback, throughput, new connections,
  top apps and live sockets.
- **Navigation.** A new **OVERVIEW** group holds Agent Dashboard first and Network second;
  **MONITORING** now starts at Live Connections. The PROTECTION order is unchanged.
- **One audit load.** The dashboard shares the existing `AgentsPageViewModel`, so opening it does
  not start a second Blackbox audit or duplicate its polling.
- **Verification.** `Axiom.UI.Avalonia` builds with 0 warnings and 0 errors; the Avalonia UI test
  suite passes 36/36, including headless navigation through all 13 pages.

## What's in 0.14.0

- **Dashboard hierarchy.** The full-width System status card moved out of the Dashboard into the
  page header, between the page title and the theme selector. The Dashboard now starts with the KPI
  row, **Agent activity** sits above the **System-wide throughput** chart, and the Active sockets,
  Processes, Loopback and Throughput cards use tighter padding, smaller value type and shorter
  accent bars.
- **Protection navigation order.** The PROTECTION group now reads **Agent Protection, Agent
  Activity, Network Control, Privacy Shield**, with the group header starting on Agent Protection.
- **Rollup.** Includes the 0.13.2 reliability fixes (AI Analyst key handling, live-history
  `last_seen`, Events filter races, evidence tail reads, OpenCode bridge errors), the 0.13.x
  Antigravity UI work, and the 0.12.0 service-owned network recovery / enforcement foundation.
  No new enforcement, DNS or firewall behavior is introduced by the 0.14.0 layout changes.

## What's in 0.13.2

- **Fixed AI Analyst API key clearing on Save (#270).** Clearing `ApiKeyInput` in the UI after
  `SaveSettings()` no longer triggers `OnApiKeyInputChanged` to overwrite the active in-memory
  `_apiKey` with an empty string and mark it dirty for the next save.
- **Fixed unchanged active connections disappearing from recent history queries (#268).**
  `HistoryStore.UpsertAsync` now updates `last_seen_utc` whenever the snapshot capture timestamp
  advances (while still suppressing duplicate writes for identical snapshot timestamps), so
  long-lived active connections remain visible in 15m/1h `Network Events` filters.
- **Fixed `Events` page dropping filter changes while a history query is in flight (#269).**
  `EventsPageViewModel.RefreshAsync` queues a pending refresh when `SelectedRange`, `SearchText` or
  `SelectedCategory` changes during an active query and discards stale responses before applying
  results.
- **Fixed `AgentEvidenceStore` tail-reader truncation for >512-byte records (#271).**
  `ReadTailEvents` in `Axiom.Presentation` and `Axiom.UI` now expands the tail read window in chunks
  until the requested record count is satisfied or byte 0 of `agent-evidence.jsonl` is reached.
- **Fixed unhandled child-process / stdin error in OpenCode lifecycle bridge (#272).**
  `OpenCodeProtection.BuildLifecycleScript` registers `error` handlers on both `child` and
  `child.stdin` before writing the JSON payload so a missing executable (`ENOENT`) or closed pipe
  (`EPIPE`) never raises an unhandled error in the host.
- **Fixed SPDX header comment in `scripts/publish-setup.ps1` (#267) and added automatic PR/push
  build & test CI workflow (`.github/workflows/ci.yml`, #273)** including parse-only validation of
  all PowerShell scripts.

## What's in 0.13.1

- **Fixed `"No new agent activity since ..."` false-positive warning & added live Antigravity session discovery.**
  - `AntigravityProtection`: writes `hooks.json` and `axiom-antigravity-hook.py` without a UTF-8 BOM
    (`new UTF8Encoding(false)`) so Antigravity's Go `language_server` (`encoding/json`) parses
    `~/.gemini/config/hooks.json` cleanly, and formats the `PreToolUse` command without embedded
    double quotes so Go's `exec.Command("cmd", "/c", command)` never injects `\"` into `cmd.exe`.
    `HasOwnedHook()` detects and repairs legacy BOM or quoted hook entries automatically.
    The hook invokes `plugins.blackbox.guard.hooks.on_pre_tool_call` in-process and records direct
    evidence into `%LOCALAPPDATA%\Axiom\agent-evidence.jsonl`.
  - `AgentSessionReader`: added `ReadAntigravity()` to read `~/.gemini/antigravity/conversation_summaries.db`
    along with live transcript/WAL write timestamps (`brain/<id>/.system_generated/logs/transcript.jsonl`
    and `conversations/<id>.db-wal`) so active Antigravity conversations appear in the `Agents`
    sessions list alongside Claude Code, Codex and OpenCode.
  - `ActivityFreshness` & `AgentsPageViewModel`: freshness now considers Blackbox audit events,
    local hook evidence (`agent-evidence.jsonl`) and active agent session timestamps, and distinguishes
    between an idle period with no running agent session (`IsStale = false`, `"Last agent activity at ... Â· no active agent session right now."`)
    and an active session where hooks have stopped firing.
  - `AgentHookProbe` & `SecurityPageViewModel`: added `"antigravity"` probe support (`TestAntigravityAsync`)
    and included Antigravity in `Install/repair agent hooks` status output.
- **Code & performance audit optimizations (snappy UI & zero background lag).**
  - `AgentEvidenceStore`: replaced full-file `File.ReadLines` every 3 seconds with a 64 KB tail seek
    and `(LastWriteTimeUtc.Ticks, Length)` cache.
  - `AgentProcessProbe`: cached `Process.GetProcesses()` snapshot for 2 seconds and disposed all
    `Process` handles immediately to prevent native handle leaks.
  - `ProcessMetadataProvider`: cached `WinVerifyTrust` Authenticode checks and `FileVersionInfo` by
    `(NormalizedPath, LastWriteTimeUtc.Ticks)` (`_imageCache`) and added `SeenProcessIds` to avoid
    repeated WMI `Win32_Process` queries per connection poll.
  - `IActivatablePage` & diff-based `ObservableCollection` updates: background pages (`Overview`,
    `Connections`, `Apps`, `Events`) skip UI rebuilds while inactive, update rows in-place when keys
    match, and `AgentsPageViewModel.Activate()` performs a 1-page incremental merge (`MergeActivity`)
    instead of re-downloading 24 pages (11,740 audit entries) on every tab switch.
  - `PrivacyShieldPageViewModel`, `PrivacyShieldBlockedHistoryStore`, `ProtectionSettingsStore` &
    `ProtectionController`: throttled `NetworkInterface.GetAllNetworkInterfaces()` to 15s, added
    in-memory write-through caching for blocked-domain history and protection settings, and disposed
    `WindowsIdentity.GetCurrent()` cleanly.

## What's in 0.13.0

- **Antigravity UI/UX overhaul & upgraded Glass themes.** Rebuilt `Dark` (Antigravity Carbon/Zinc)
  and `Light` (Antigravity Studio/Paper) palettes, plus upgraded `Axiom Glass Dark` (Frosted
  Obsidian) and `Axiom Glass Light` (Frosted Pearl) with crisp translucent surfaces, 1px borders,
  and refined typography (`Classes="mono"` for IP:port, PIDs, SHA-256 hashes, timestamps and paths;
  `Classes="table-header"` for structured column headers; `Button.danger` for destructive actions).
- **Full right-click context menus & interactive actions across all pages.** Right-clicking any row
  automatically selects it and opens context actions across `Events`, `Overview`, `Connections`,
  `Apps`, `Firewall`, `Privacy Shield`, `Security` and `AI Analyst` â€” including inspecting event
  details, copying rows/paths/endpoints/hashes/domains, blocking outbound/inbound traffic, and
  ending tasks (`End task`).
- **Network recovery hardening.** `WindowsDnsRecoveryAdapter.Run` now reads `stdout`/`stderr`
  asynchronously before `WaitForExit` so hung external commands honor the 15-second timeout;
  DNS read-back verification preserves server ordering (`SequenceEqual`); `NetworkRecoveryCommand`
  checks for reparse points before reading snapshots; and `NetworkRecoveryController.CaptureNow`
  re-applies `%ProgramData%\Axiom` ACL hardening after writing the default snapshot.

## What's in 0.12.0

- **Service-owned network recovery.** DNS and Axiom-owned firewall state are captured by the
  elevated service into a checksummed machine snapshot, restored only from that validated snapshot,
  and verified by read-back. The service watchdog restarts a stopped resolver before any DNS-only
  rollback and never disables an intentionally active protection because the desktop closed.
  An explicit administrator `--recover-network --apply` path exists for a stopped service.
- **Agent enforcement foundation.** URL paths are rejected by default in threat-share payloads
  (B2); module endpoints must prove their owning process (B3); ambiguous reporter outcomes stay
  unverified instead of being retried blindly (B4). Adds the E0 capability matrix, the E1
  deterministic offline policy engine, E2 host hook-event/deny-payload mapping, and the E5
  cooperative enforcement status surface. No autonomous enforcement or live publication is added.
- **Avalonia UI polish.** Navigation, card surfaces, active theme/effects toggles and the session
  context menu were tightened, with unit coverage for the active-state flags.
- **Documentation.** Enforcement baseline/capability ADRs, the enforcement tracker, leadership
  titles, and the network-recovery snapshot/rollback/emergency runbook.

## What's in 0.11.0

- **Public release line resumes after 0.10.25.** This release rolls up the 0.2.0 provenance work
  (list-only matches stay local, local source/version/Axiom provenance, fail-closed AI provenance)
  and the 0.3.0 work (user-triggered Check graph, installer upgrade while the service runs).
- **Release ordering is guarded.** `scripts/build-release.ps1` now refuses a version that is not
  greater than the highest existing `v*` tag, because GitHub sorts releases by semantic version.
  The short 0.2.0/0.3.0 reset stays as historical snapshots.
- Version `0.11.0` is greater than the previous public tag `0.10.25`, so the new release appears
  above it; future 0.11.x releases continue normally.

## What's in 0.3.0

- **AI Analyst provenance fails closed.** If the local list/provenance lookup fails, no AI
  indicator is queued; independence cannot be established from an empty fallback set.
- **User-triggered Check graph.** Blocked domains have a read-only **Graph** action that asks the
  local Blackbox `/api/threat` endpoint for public, local and community tiers, with a 5-second
  bound, a 10-minute/256-entry cache and no work on the per-connection path. Not found and
  unreadable results are explicitly **Unknown, not clean**; no VERIFIED or COMMUNITY badges are
  shown.
- **Version numbering reset** to `0.3.0` (from `0.2.0`, after the earlier `0.10.x` sequence);
  portable/Setup upgrade compatibility and the Store/MSIX caveat are documented in the release
  notes.
- **Setup can upgrade while the Windows service runs.** Only a running desktop blocks Setup; an
  interactive service copy in the install directory is stopped before copying, and the registered
  service is replaced by the elevated service installer.

## What's in 0.2.0

- **Public-list matches stay local.** Privacy Shield no longer proposes blocked malware-list
  domains to Blackbox/DKG. Every install matches the same URLhaus list, so those reports looked
  like independent corroboration when they were one list echoed back.
- **Local provenance is recorded.** Blocked events store the matched rule, source id/name/version,
  Axiom version, detection reason, timestamp and the blocked/not-fetched distinction. This stays
  local and is shown in the blocked-history tooltip.
- **AI Analyst suppresses list-derived values.** A structured indicator whose domain already
  appears in the local malware-list block history is not proposed, even if the model labels it
  malicious. Evidence-bound indicators that are genuinely independent remain eligible.

## What's in 0.10.25

- **Axiom uses the DKG node Blackbox already runs.** When no standalone node answers on 9200,
  the DKG card follows `dkg_url` from Blackbox's graph status and labels it "reported by
  Blackbox". A complete installation skips Axiom's own unused DKG node when Blackbox reports its
  node reachable, avoiding a second node and port collision.

## What's in 0.10.24

- **Module cards no longer claim Axiom cannot start a module.** When DKG or Blackbox is not
  running, the status now says to press **Start** in Axiom or use `dkg start`, matching the Start
  button that has existed for both modules.

## What's in 0.10.23

- **Hermes and Blackbox use one resolved profile path.** The reporter, consent check, mode store,
  local state and uninstaller now resolve `HERMES_HOME`, then `%LOCALAPPDATA%\hermes`, then the
  legacy `~\.hermes` in one place, with `BLACKBOX_HOME` as an override. The threat-sharing card
  shows the profile path and whether its consent and reporter key exist.

## What's in 0.10.22

- **A module is connected only when it identifies itself.** DKG requires `/api/status` with
  `version`, `peerId` (`12D3Kooâ€¦`), `nodeRole` and a known testnet/mainnet `networkId`; Blackbox
  requires `/api/graph-status` with `mode`, `node_reachable`, `dkg_url` and `sync_progress`.
  Anything else on 9200/9700 is reported as `UNKNOWN` instead of a green module.

## What's in 0.10.21

- **DKG installs a pinned testnet build.** Axiom now installs
  `@origintrail-official/dkg@10.1.0` from an embedded lockfile with `npm ci`, instead of npm's
  `latest` tag, which is the mainnet build. An existing Axiom-managed install with another version
  is stopped and upgraded.
- **The node no longer updates itself every five minutes.** The installer sets
  `autoUpdate.enabled=false` in `DKG_HOME\config.json`, so the version Axiom installed is the
  version that runs.
- The DKG status line also shows the node's network name when `/api/status` returns it.

## What's in 0.10.20

- **Transient reporter failures no longer discard indicators.** A timeout, missing CLI, offline
  node or unknown failure now marks the item `deferred` with an attempt count and a backoff time
  (5 minutes, doubling up to 6 hours); only an explicit schema or policy refusal is rejected.
- **The daily cap leaves the item queued.** Reaching the reporter's cap no longer consumes the
  indicator or records a rejection; it stays pending for the next day.
- The queue shows deferred items and their retry time, and `Send now` only retries those whose
  backoff has passed.

## What's in 0.10.19

- **Shared URLs no longer carry secrets.** A URL indicator is reduced to scheme, host, non-default
  port and path: userinfo, query strings and fragments are dropped, and loopback, private, `.local`
  and single-label hosts are rejected.
- **IP normalisation covers the special-purpose ranges.** `0.0.0.0/8`, CGNAT `100.64/10`,
  documentation, benchmarking, AS112/AMT anycast, multicast and reserved IPv4, plus IPv6
  translation, discard-only, `2001::/23`, documentation, 6to4, ULA, link-local and multicast.
  IPv4-mapped IPv6 is checked as IPv4.
- The README now shows the Overview page so the application is visible before the feature list.

## What's in 0.10.18

- **AI Analyst indicators are structured and evidence-checked.** The analyst result may now carry
  an `indicators` array; Axiom proposes only `role: malicious` entries whose value matches a remote
  endpoint it put in the evidence package. Prose, observations, evidence references and suggested
  actions are no longer scanned, so a benign domain in a comparison or a block recommendation cannot
  become a report.

## What's in 0.10.17

- **Threat sharing waits for you.** A queued indicator is no longer signed and sent on a one-minute
  timer. Each row now has **Share**, and **Send now** sends the reviewed queue; nothing is sent
  while sharing is off. The card and queue text say so instead of "waiting for review" over an
  automatic send.

## What's in 0.10.16

- **Broken punctuation is repaired.** An earlier encoding conversion had replaced `â€”`, `Â·`, `â€¦`
  and `Ã—` with the Unicode replacement character in the Privacy Shield and Agents pages, which the
  UI rendered as `?`. The adapter list now reads `Ethernet 2 â€” default route Â· DNS 127.0.0.1`,
  profile names and counters use `Â·` again, and the same repair restores arrows, box drawing and
  multiplication signs in the README and the Avalonia migration baseline.

## What's in 0.10.15

- **Browser secure DNS (DoH) is now detected.** Privacy Shield reads the Chrome and Edge
  `Preferences` files and the Firefox `prefs.js` files and warns when a browser resolves names
  through its own DoH provider instead of the Axiom resolver. The warning names the browser and
  profile, and says where to turn secure DNS off. Detection only; no browser setting is changed.
- The warning is honest about its limits: Windows system DoH is not read, because it applies to a
  public DNS server and an adapter pointed at 127.0.0.1 has no DoH template.

## What's in 0.10.14

- The Antigravity row in **Protected workspaces** shows its proper name and detects the running
  Antigravity process, so the detail switches from "start Antigravity" to the runtime hint.

## What's in 0.10.13

- **Antigravity now has an Axiom hook.** Axiom writes a PreToolUse entry into
  ~/.gemini/config/hooks.json that runs the Blackbox guard; a deny decision blocks the tool call,
  and every call is recorded as antigravity evidence. The Agents page lists Antigravity as a
  protected harness when the hook is installed.
- The user's existing hooks.json entries are merged, never replaced. Antigravity must be restarted
  after the hook is installed (it reads hooks at start).

## What's in 0.10.12

- **Antigravity is recognised as an agent executable** for ask-queue priority and agent lockdown. It
  has no hook integration, so it does not appear in the hook evidence or protected-harness list; the
  Agents page says so explicitly.
- The stale-activity hint now explains that an agent keeps the hook it loaded at start, so it has to
  be restarted after an Axiom update before it reports again.

## What's in 0.10.11

- **Shield decisions survive application updates.** An allow or block is matched by a path family
  that ignores version and hash folders (GoogleUpdater\157.0.8089.0\updater.exe,
  Codex\bin\<hash>\codex.exe, WindowsApps package folders). The updated executable inherits the
  decision instead of asking again, and an inherited block creates its outbound rule for the new
  path.

## What's in 0.10.10

- **Stalled agent activity is visible.** The Overview activity card shows how old the newest
  recorded event is, and the line turns amber after 15 minutes with a pointer to the dashboard or
  the agent hooks. A dashboard that answers its API but receives no events no longer looks like a
  frozen page.

## What's in 0.10.9

- **HaGeZi list is pinned.** The source URL names a commit instead of @latest, and the updater
  verifies its SHA-256 before rebuilding the ruleset; a mismatch keeps the previous rules.
- **Single-label entries are rejected.** A list line without a dot can no longer block an entire
  TLD such as com; invalid lines are skipped like other malformed input.

## What's in 0.10.8

- **Disk writes stay small on an idle desktop.** History persists only connections that survived a
  refresh, every two minutes instead of every two seconds; only new or changed flows are written;
  ephemeral local ports collapse into one row per remote; throughput is batched every five minutes;
  blocked-query history is buffered in RAM for 30 seconds; and retention plus the full last-seen
  refresh run every six hours.
- **Measured:** the service wrote about 1.2 MB/s before and about **1.2 KB/s** after, with the
  desktop closed (roughly 0.1 GB/day instead of more than 100 GB/day).
- The installer waits for a pending service stop and retries the image copy, so replacing the
  protected service image no longer fails with exit code 7.

## What's in 0.10.7

- **The service image is protected.** It is installed under `%ProgramFiles%\Axiom\Service` with a
  SYSTEM/Administrators-only ACL, the copy is hash-checked, and an older install that still points at
  the user profile is repaired on the next start. A medium-integrity process can no longer replace
  the LocalSystem binary.
- **ProgramData is no longer plantable.** `%ProgramData%\Axiom` is created SYSTEM/Administrators
  only, inheritance is removed, junctions are refused, settings are written through a random temp
  file, and the legacy migration refuses a junction.
- **DNS restore trusts only the machine snapshot.** Restore and the SYSTEM failsafe reject a
  reparse point or a file not owned by SYSTEM/Administrators, accept only parsed IP addresses, and
  fall back to DHCP when the snapshot cannot cover an adapter.
- **Upstream DNS replies are validated.** A reply whose transaction id or question does not match
  the query is dropped and the next upstream is tried.
- **Inbound allow rules are rejected on the local pipe**, even for the allowed user.
- Smaller items: a 2 MB cap on the community feed, an accurate lockdown hint (exact files, not
  renamed copies), and an `https://` URL in the integration documentation.

## What's in 0.10.6

- **One DNS entry is no longer a single point of failure.** Pointing an adapter at the Privacy Shield
  resolver keeps the adapter's previous DNS servers behind `127.0.0.1` as a fallback. If the resolver
  stops or stops answering, Windows fails over and names keep resolving; filtering is bypassed until
  the resolver is back, and the Adapter DNS card says so.
- Only a family with a real fallback is changed, so the helper never writes a single-server adapter.
- The Adapter DNS warning now distinguishes a dead network from a silent filtering bypass.
- The service failsafe from 0.10.5 still restores the saved DNS on disable, stop or a failed start.

## What's in 0.10.5

- **Blocked query history is grouped by application.** Each app is one expandable row with its block
  and domain counts; opening it lists every blocked domain with category, count, last time and the same
  Allow/Block actions. The list scrolls inside its card.
- **A stopped resolver can no longer leave an adapter without DNS.** On disable, service stop or a
  failed resolver start, the service restores the saved adapter DNS itself (no UAC prompt), and falls
  back to DHCP when no snapshot exists. The UI also warns and alerts while any adapter still points at
  127.0.0.1 but the resolver is not running, and the adapter list is refreshed from real DNS state.
- **Incident:** the LAN outage came from disabling Privacy Shield while Ethernet DNS stayed at
  127.0.0.1; Ethernet was restored to DHCP and the new warning covers that case.

## What's in 0.10.4

- **Privacy Shield live list is grouped and bounded.** Blocked queries fold into one row per
  domain and app with a count, the top six are shown by default, **Show all** opens up to 40, and the
  lists scroll inside the card instead of growing the page. Blocked history is capped at 250 rows.
- **Adapter DNS sits above the lists.** The explicit UAC helper is its own card directly under the
  resolver statistics, so it no longer ends up below the blocking lists.
- **Power usage traced to the Blackbox dashboard.** A long-running dashboard process was busy-looping
  at about 200% CPU; restarting it returned to idle (Axiom's service stayed near 0% at idle).
  Known limitation: Codex CLI on Windows reports hook failures and never executes them, so Codex
  tool calls are not audited until that is fixed upstream.

## What's in 0.10.3

- **Agent tool fetches are attributed to the agent.** Agents fetch through tools (curl, git, nslookup),
  so the DNS query belongs to the tool child, not the agent process. Axiom now walks the parent chain
  (up to six levels) once per process and remembers the nearest agent ancestor, so a malware-list
  domain fetched that way is still a truthful etched-by-tool sighting.
- **Verified live.** With the adapter pointed at the resolver, a malware-list domain fetched by an agent
  tool produced a candidate, was submitted by the desktop, and the DKG accepted it: the report is in
  the community's shared memory (ioc:domain:win.down.55kantu.com, stage eported Â· monitor).

## What's in 0.10.2

- **Corrected the threat-sharing note.** 0.10.1 added a theme-coloured note under the sharing
  description, but its wording overstated the effect: it implied every report strengthens the graph and
  that Axiom itself detects better because of it. The note now says what actually happens - reports are
  community sightings, independent nodes can corroborate them, Blackbox can flag them and curators can
  promote strong evidence into the verified blocking tier - and states that Axiom's own firewall and DNS
  filtering still decide only from local lists and rules.

## What's in 0.10.1

- **Threat sharing now explains why it helps.** A theme-coloured note was added under the sharing
  description (its wording was corrected in 0.10.2).

## What's in 0.10.0

- **Axiom can propose indicators to the Blackbox community graph, but only honest ones.** With
  threat sharing on, the Agents page now shows a preview list of indicators Axiom actually observed:
  malware-list domains that an **agent process** fetched, and high-confidence AI Analyst IOCs. Each
  candidate carries the exact evidence that qualifies it and can be dismissed before it is sent.
- **Ads, tracking and telemetry are never proposed.** Blackbox's schema has no ad or spam category,
  and mass-reporting them would be noise. The Privacy Shield catalog now has a dedicated malware-only
  source - URLhaus malicious domains via malware-filter (MIT, updated every 12 hours) - so a malware
  label is real. OISD is labelled as ads/tracking only, and a malware source upgrades the category of
  a domain already listed by another source.
- **Nothing is sent by the service.** The service attributes the DNS query, keeps the durable queue
  and records outcomes. Submission runs the Blackbox reporter (`blackbox report --type ioc`) in the
  signed-in user's own session, because that profile holds the reporter key, DKG identity and the
  reporter-terms consent. Blackbox enforces consent, cooldown, the 100/day cap and its high severity
  floor; Axiom shows the exact outcome per indicator.
- **Off means off.** With sharing off the queue only exists as a preview and a submission attempt is
  refused with the CLI's own message. Enabling sharing sends queued indicators automatically (at most
  once a minute), and the Agents page keeps the last outcomes visible.

## What's in 0.9.0

- **System-wide throughput now has real history.** The Overview range picker offers **5m, 1h, 12h,
  24h, 7d and 30d**. The 5-minute view remains the live 1-second measurement in the desktop process;
  every longer range is read from the Axiom service, which samples the same interface counters and
  stores one row per minute in the local SQLite history.
- **Honest rates and honest gaps.** A bucket is drawn as bytes divided by the seconds actually
  observed in it, and a minute without a measurement stays a gap instead of an invented idle line.
  History starts when the service first runs and follows the existing 30-day retention (about a few
  MB of rows per month).
- **Clear failures.** Without the service the chart says that history is unavailable and why,
  instead of drawing nothing under a working label. An open historical range refreshes itself every
  30 seconds; the live counters keep updating while a longer range is selected.

## What's in 0.8.1

A post-reboot fix release for the 0.8.0 installation. Everything below was reproduced on a machine
where Axiom started from its login entry and corrected there.

- **The tray icon is actually registered.** A `TrayIcon` created in code stays detached until it is
  part of the application's `TrayIcons` collection, and a detached icon is never sent to the shell:
  Axiom reported that it runs in the background but nothing appeared next to the clock. The icon is
  now attached after the window shows and is detached on exit. A shell failure is written to
  `%LOCALAPPDATA%\Axiom\tray-error.log`, and close-to-tray is disabled instead of stranding the app.
- **Module consoles stay hidden.** When the Blackbox installer starts the DKG node and dashboard
  from its own login tasks, their `node.exe` console used to stay open because the existing hider
  only followed descendants of the desktop process. The new module hider matches the Axiom and
  Blackbox module command lines (including `%LOCALAPPDATA%\hermes\blackbox`) and hides their
  top-level window; an unrelated user Node.js window is never touched.
- **Core protection comes up first.** The 43 MB Privacy Shield ruleset is loaded on a background
  task instead of the service constructor, so the service pipe, the firewall consent and the monitor
  are available while the optional DKG/Blackbox modules are still loading. Measured cold start on
  the installed service: process running in 0.5 s and the resolver answering in 3.9 s.
- **The resolver no longer grows the service.** The compiled DNS policy (about 190 MB of managed
  objects for 300,000 domains) is built once and reused until the settings or the ruleset change; a
  status poll no longer rebuilds it. The ruleset is streamed from disk instead of read into a 43 MB
  string, and the large object heap is compacted once after the startup load. The service now idles
  at 230-285 MB working set instead of 500-900 MB with spikes toward 1.6 GB.
- **Memory attribution.** The DKG and Blackbox `node.exe` workers are separate processes
  (`%LOCALAPPDATA%\hermes\...` and `%LOCALAPPDATA%\Axiom\modules\dkg\...`); their several hundred MB
  is not part of the Axiom service footprint.
- **Task Manager grouping is an OS limit.** Task Manager groups by executable, so `Axiom.Service.exe`
  and the module `node.exe` workers cannot be folded into the `Axiom.Desktop.exe` group, and Axiom
  cannot change that grouping.

**Known gaps in 0.8.1** are the same as for 0.8.0: no ETW telemetry yet, TCP-only traffic totals, no
reputation feed, and Axiom reports only its own firewall rules.

## What's in 0.8.0

- **Axiom is now positioned as free, open-source network and AI-agent security.** The app title,
  header, footer and installer/shortcut descriptions use the new product description.
- **AI Analyst works with the OpenChamber/OpenCode installation you already have.** A built-in
  `opencode://local` provider starts the local OpenCode CLI in headless plan mode, so no Ollama, LM
  Studio, extra API key or separate local server is required. The default model is
  `opencode-go/deepseek-v4.1-flash`; OpenAI-compatible, OpenAI, Anthropic, DeepSeek and Z.ai providers
  remain available.
- **AI evidence v2.** The analyst now receives parent process and parent chain, Authenticode signer
  status and subject, product/version, sanitised command line, observed duration, well-known remote
  port names, local host/subnet/gateway context, Axiom-owned firewall rule status and an aggregated
  30-day local flow baseline. It no longer reports baseline truncation or `ruleStatus Unknown`.
- **Copy and progress in AI Analyst.** Copy result and Copy all export every field as text. An
  indeterminate progress bar, elapsed seconds and Cancel are shown while the agent is working; the
  result panel returns to the top when a new finding arrives.
- **Settings notifications and window privacy.** Notifications, the tray icon and background console
  window hiding are separate switches. Axiom can hide Node, PowerShell, Python, cmd, DKG, OpenCode
  and conhost windows that belong to processes it launched, without touching the user's own windows.
- **Axiom Shield usability.** Remembered Shield decisions now support Block and Unblock from a button
  or the right-click menu. Pending rows show the remote `IP:port`, the trigger explanation and a
  clear "not a malware verdict" note; Microsoft-signed processes are filtered with a visible count.
- **Durable Shield ask queue.** A pending application stays listed after its connection ends until
  the user chooses Allow, Block or Dismiss, and every pending application remains visible. Dismiss
  hides it until the application opens a new connection. The alert banner and each row expose
  Allow/Block/Dismiss.
- **Alerts that lead somewhere.** A Shield alert navigates to Firewall, highlights the exact
  application and scrolls to it. Alerts are kept in the bell history even when notifications are off.
- **Window and lifecycle polish.** Native resize cursors, drag resize, Win+arrow snap, edge snap,
  double-click maximize/restore, working caption buttons, a 900Ã—600 minimum, responsive status/Firewall
  layouts, close-to-tray, start-minimized and clean `ShutdownRequested` handling.
- **DKG startup and evidence.** When the local DKG node is installed, Axiom starts it on launch if it
  is not already answering, verifies the supervisor/worker and `/api/status`, and never starts it in
  Standard mode.
- **Branding and rendering.** The high-resolution lockup uses high-quality interpolation and the
  exact 3:1 aspect ratio, with layout rounding enabled for a crisp header.
- **Privacy Shield is live and actionable.** Blocked DNS queries are attributed to the requesting
  application through the Windows UDP/TCP owner tables and shown in a 2-second list with app
  name/path, category and time. Each row offers **Allow** and **Block**: Allow adds a custom
  allowlist entry and turns the row into Block, Block reverses it. The catalog has five
  licence-labelled sources â€” HaGeZi Multi PRO and OISD Big (GPL-3.0), WindowsSpyBlocker (MIT), and
  The Block List Project Ads/Tracking (Unlicense) â€” downloaded from upstream at runtime, never
  bundled.
- **Privacy Shield survives upgrades and explains zero statistics.** Installed-service settings and
  compiled rules live in `%ProgramData%\Axiom\` with a one-time copy from the old service profile;
  the blocked-query history stays in the service profile. When the resolver runs but no adapter
  points at `127.0.0.1`, the statistics panel says so and points to the UAC helper; the adapter row
  shows `127.0.0.1 Â· Privacy Shield`, including after an app restart.
- **Connections grouped by application with real traffic totals.** The page opens grouped and shows
  cumulative TCP megabytes sent/received plus the realtime rate from the latest poll
  (`now â†‘ â€¦ Â· â†“ â€¦` or `now idle`). Sort by total, sent, received, sockets or name in either
  direction from the action toolbar. Expanded groups and their rows survive the one-second refresh;
  UDP-only apps say `traffic not measured`.
- **Agent sessions now include OpenCode/OpenChamber.** The Agents and Agent Stats session cards read
  Claude Code, Codex and OpenCode/OpenChamber metadata (read-only). A session shows **live** when its
  host process runs or its data changed in the last five minutes, so the active OpenCode session no
  longer appears as historical; raw session ids stay hashed.
- **Threat sharing is visible on the Agents page.** A card mirrors the Blackbox dashboard state
  (`off Â· opt in` or `on Â· signed, redacted`) and offers **Enable/Disable threat sharing** with a
  confirmation when enabling. It reads and writes the dashboard's signed, redacted `report` setting;
  prompts, commands, file paths, credentials, model content and raw session ids are never sent.
- **Buttons follow the active theme.** The Fluent grey default is replaced by Axiom palette
  surfaces, themed borders, accent hover/press and disabled states, with an accent primary style
  for Apply/Analyze/Export/Configure/Shield. All four themes use the same styles.
- **Installer profiles: Complete versus Partial.** The setup explains both before writing anything.
  **Complete** uses one UAC prompt to register and start the service, then enables Axiom Shield
  (`ask` policy), the Privacy Shield resolver (Balanced, five sources downloaded and compiled up to
  the 500,000-entry cap), notifications, tray icon, background-console hiding and start with
  Windows, and installs Blackbox, DKG and agent hooks. **Partial** stays administrator-free with
  every module opt-in. The applied profile is recorded in
  `%LOCALAPPDATA%\Axiom\install-profile.json`; a declined elevation produces a warning instead of
  silently claiming complete protection.

**Known gaps in 0.8.0:** ETW telemetry is not integrated yet, so SNI, TLS certificate subjects, DNS
query names, per-packet byte counts and TIME_WAIT ownership remain missing evidence. Axiom measures
per-application totals from Windows extended TCP statistics only (TCP, one-second poll; UDP is not
measured). There is no reputation/threat-intelligence feed, command lines are sanitised and
truncated, and Axiom reports only its own firewall rules rather than the effective Windows default
policy.

## What's in 0.7.6

- Connections rows and Overview live sockets now expose the same actions as Applications: **Block
  outbound**, **Block inbound**, **End task** and **Copy path**, as buttons above the table and in
  the row context menu. Every action confirms first.
- Agent Stats sessions gained **Copy session details** in the row menu, as in the WPF application.
- The Connections action menu covers both the flat and the grouped view.

## What's in 0.7.5

- Module health now samples every 5 seconds and keeps a fixed 30-check window. The strip always
  shows 30 slots: filled squares for recorded checks, outlined squares while the window fills.
  The summary reads `n/30 checks` with per-module uptime and the last check time.
- The DKG module Start action now falls back to a `dkg` command installed on PATH. A node installed
  outside the Axiom folder (for example `F:\AI-Storage\dkg`) can be started from the app instead of
  only from a terminal. DKG still never starts on its own.
- The module summary no longer reports the oldest sample as the last one.

## What's in 0.7.4

- New **Agent Stats** tab between Agents and Firewall. It collects every agent statistic that used
  to be buried in the Agents tab: session, API-call, tool-call, install, file-access and threat
  counters, a findings summary, the local Blackbox activity feed with filters and details, agent
  sessions, hook evidence and findings.
- The **Agents** tab is now only about state and control: modules, protection status, workspaces and
  hooks, health and the verified graph. No behaviour history remains there.

## What's in 0.7.3

- Agents page restores the **Module health** history from the WPF application: one small square per
  loopback health check, green when DKG or Blackbox answered, muted when the module was not running.
  A summary shows the sample count, how many checks saw each module and the last check time.
- The two module cards now carry a live health square next to the title (green connected, muted not
  connected) with the state on hover.

## What's in 0.7.2

- Agents page now uses a traffic light for every detected hook: **green** when the hook is connected
  or verified, **orange** when it is installed but still needs a test or host trust, **red** when the
  guard failed or is offline, grey when nothing is detected. Legend added above the list.
- **Test hook** now updates the badge, not only the text: a passing test turns the row green, a
  failing test turns it red, and the result survives status refreshes.
- Badges show the reason on hover.

## What's in 0.7.1

- Fixes the first live enforcement pass: INetFwRule rejects a port scope while the protocol is
  "any", so the property is now only written for TCP/UDP. A stale scope is repaired by rebuilding
  the Axiom-owned rule once.
- Read-back now compares remote addresses as network/prefix pairs, because Windows rewrites IPv4
  CIDR to address/mask notation. The 16-range agent lockdown scope applies and verifies.
- Verified end to end on Windows: block rule created and read back, test executable loses network,
  allow removes the rule and restores it.

## What's in 0.7.0

- **Axiom Shield.** A complete installation turns protection on during setup; a partial installation
  leaves it off until you enable it on the Firewall page. Axiom installs and starts its Windows
  service (one administrator approval), then enforces through Windows Firewall. The desktop app
  stays unprivileged.
- **Ask policy.** Every new outbound application is listed with its path, socket count and first-seen
  time until you choose **Block** or **Allow**. A block is an Axiom-owned rule; allow is recorded so
  the application is not asked again.
- **Agent network lockdown.** One switch blocks internet access for detected agent executables
  (OpenCode, Codex, Claude and similar) while keeping localhost reachable, so the local Blackbox
  guard keeps working.
- Disabling the shield removes every Axiom-owned rule and clears the decisions.
- Includes the 0.6.5 Overview layout and agent activity panel.

## What's in 0.6.5

- Overview puts **Agent activity** directly under the throughput chart, above **New connection events**
  and **Top applications**, as in the WPF application.
- The Overview agent panel matches the WPF layout: audit description, filters, activity counts and
  finding summaries, TIME/AGENT/EVENT/DETAILS/SECURITY/SEVERITY columns with threat colouring,
  a scrollable **Activity details** pane and copy actions.
- Includes the 0.6.4 event-selection fix.

## What's in 0.6.4

- Overview **New connection events** keeps the selected row and its details across live refreshes;
  the selected event is pinned in the visible list while it remains in the time window.
- Includes the 0.6.3 tab order and Overview Agent activity work.

## What's in 0.6.3

- Navigation order matches the WPF application: Overview, Connections, Applications, Events,
  Agents, Firewall, Security, Privacy Shield, AI Analyst, Support, Settings.
- Overview restores the WPF **Agent activity** panel with filters, security outcomes, details and
  copy actions.
- Includes the 0.6.2 theme parity work.

## What's in 0.6.2

- Avalonia palettes now use the exact WPF Dark, Light, Dark Midnight and Light Warm values.
- Navigation and data-row selection use the WPF nav-selected/accent-soft colours instead of Fluent blue.
- Chart upload/download colours and primary buttons follow the WPF accent tokens.
- Includes the 0.6.1 footer, GitHub/Donate, theme selector and status badges.

## What's in 0.6.1

- Restored the sidebar product footer: Axiom icon, version, description, GitHub and â™¥ Donate.
- Added the top-bar theme selector and status-bar mode/firewall badges.
- Includes the 0.6.0 Avalonia cutover.

## What's in 0.6.0

- **Avalonia is now the primary Windows UI.** The installer ships `Axiom.Desktop.exe` from
  `Axiom.Desktop.Avalonia.Windows`; the WPF application remains in source as a fallback.
- All eleven pages are ported: Overview, Connections, Applications, Events, Firewall, Privacy Shield,
  Security, Agents, AI Analyst, Support and Settings.
- Live throughput chart, full socket filters and grouping, session first-observed events, top
  applications, native verified threat graph, selectable threat details, protected workspaces and
  agent module cards.
- Four real palettes (Dark, Light, Dark Midnight, Light Warm), custom Axiom title bar, tray icon,
  single-instance handling and 1080Ã—720 shell fit.
- Ported context menus for applications, connections, overview sockets and agent evidence.
- Installer, MSIX and release scripts now publish the Avalonia host as `Axiom.Desktop.exe`.
- Includes the 0.5.3 verified threat graph and Privacy Shield source-fit work.
