# Axiom — historical change log

This is the original feature-by-feature release history extracted from the long README. Entries describe the version **at the time of release**, and earlier claims may have been corrected or superseded in later versions. For current architecture, safety and privacy behaviour see [Architecture](ARCHITECTURE.md), [Security model](SECURITY_MODEL.md), [Threat intelligence](THREAT_INTELLIGENCE.md) and [Privacy Shield](PRIVACY_SHIELD.md). Per-release build/test evidence is in [RELEASES](RELEASES/).

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
    between an idle period with no running agent session (`IsStale = false`, `"Last agent activity at ... · no active agent session right now."`)
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
  `Apps`, `Firewall`, `Privacy Shield`, `Security` and `AI Analyst` — including inspecting event
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
  `version`, `peerId` (`12D3Koo…`), `nodeRole` and a known testnet/mainnet `networkId`; Blackbox
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

- **Broken punctuation is repaired.** An earlier encoding conversion had replaced `—`, `·`, `…`
  and `×` with the Unicode replacement character in the Privacy Shield and Agents pages, which the
  UI rendered as `?`. The adapter list now reads `Ethernet 2 — default route · DNS 127.0.0.1`,
  profile names and counters use `·` again, and the same repair restores arrows, box drawing and
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
  the community's shared memory (ioc:domain:win.down.55kantu.com, stage eported · monitor).

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
  double-click maximize/restore, working caption buttons, a 900×600 minimum, responsive status/Firewall
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
  licence-labelled sources — HaGeZi Multi PRO and OISD Big (GPL-3.0), WindowsSpyBlocker (MIT), and
  The Block List Project Ads/Tracking (Unlicense) — downloaded from upstream at runtime, never
  bundled.
- **Privacy Shield survives upgrades and explains zero statistics.** Installed-service settings and
  compiled rules live in `%ProgramData%\Axiom\` with a one-time copy from the old service profile;
  the blocked-query history stays in the service profile. When the resolver runs but no adapter
  points at `127.0.0.1`, the statistics panel says so and points to the UAC helper; the adapter row
  shows `127.0.0.1 · Privacy Shield`, including after an app restart.
- **Connections grouped by application with real traffic totals.** The page opens grouped and shows
  cumulative TCP megabytes sent/received plus the realtime rate from the latest poll
  (`now ↑ … · ↓ …` or `now idle`). Sort by total, sent, received, sockets or name in either
  direction from the action toolbar. Expanded groups and their rows survive the one-second refresh;
  UDP-only apps say `traffic not measured`.
- **Agent sessions now include OpenCode/OpenChamber.** The Agents and Agent Stats session cards read
  Claude Code, Codex and OpenCode/OpenChamber metadata (read-only). A session shows **live** when its
  host process runs or its data changed in the last five minutes, so the active OpenCode session no
  longer appears as historical; raw session ids stay hashed.
- **Threat sharing is visible on the Agents page.** A card mirrors the Blackbox dashboard state
  (`off · opt in` or `on · signed, redacted`) and offers **Enable/Disable threat sharing** with a
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

- Restored the sidebar product footer: Axiom icon, version, description, GitHub and ♥ Donate.
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
  single-instance handling and 1080×720 shell fit.
- Ported context menus for applications, connections, overview sockets and agent evidence.
- Installer, MSIX and release scripts now publish the Avalonia host as `Axiom.Desktop.exe`.
- Includes the 0.5.3 verified threat graph and Privacy Shield source-fit work.
