# Axiom

**Free Open-Source Network & AI Agent Security**

**Version:** 0.10.16 | **Repository:** https://github.com/a-51-50/Axiom | **License:** GPL-3.0-or-later

> The repository is private during active development. The source license remains
> GPL-3.0-or-later; public source availability will be confirmed before a public release.

> **Development build - use at your own risk.** Axiom is under active development and may contain
> defects, incomplete features or regressions. Firewall changes can interrupt connectivity, DNS
> changes can break name resolution, and agent hooks can block tools or files. Do not rely on it as
> your only security control. Where possible, test firewall and DNS changes in a VM, keep backups
> and keep a recovery path.

Axiom is a local, offline Windows network monitor, firewall policy manager and agent-protection
console. It shows which applications use the network, which endpoints they talk to, and what
happened over time. It manages only its own rules in the built-in Windows Firewall; Windows remains
the enforcement authority. There is no account, no cloud, no advertising and no telemetry.

Axiom brings together four surfaces:

- **Network visibility and history** for TCP/UDP IPv4/IPv6 sockets and applications.
- **Axiom Shield** — one switch that installs the elevated local service and turns the ask policy
  on: every new outbound application waits for Block or Allow, and blocks are Axiom-owned Windows
  Firewall rules with read-back verification and recovery.
- **Local privacy controls** including Privacy Shield DNS filtering and a read-only AI analyst.
- **Agent protection** through Blackbox-compatible lifecycle hooks, an agent network lockdown
  (localhost only) and a local audit view.

Blackbox and OriginTrail DKG are optional. Axiom works without either; when present, they add
agent-level guardrails and signed threat-intelligence context respectively.

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

## What it covers

### Per-application network visibility

- TCP and UDP sockets for IPv4 and IPv6, read from the Windows IP Helper owner tables.
- Process attribution by PID, executable name and resolved path; unresolved or protected processes
  are marked as partial instead of being guessed.
- Local and remote endpoints, connection state, direction, loopback detection and the first time a
  flow was observed.
- **Group by app** with cumulative TCP megabytes sent and received per application, the realtime
  rate from the latest poll, and sorting by total, sent or received traffic in either direction.
  TCP totals come from Windows extended TCP statistics; UDP and flows shorter than one poll are
  marked as not measured instead of guessed.
- A sortable, filterable, virtualized table that stays responsive with hundreds of processes and
  thousands of rows.

### Agent protection

- Detects supported coding-agent workspaces and installs only Axiom-managed hook files. Existing
  user-authored hooks are preserved and backed up.
- Supported harnesses: **OpenCode/OpenChamber, Codex, Claude Code, Cursor, GitHub Copilot CLI,
  Gemini CLI, Windsurf Cascade, Cline, ZCode and DeepSeek Harness**.
- **Agent sessions** include Claude Code, Codex and OpenCode/OpenChamber metadata. The OpenCode
  database is read-only; a session is **live** when its host process runs or its data changed in the
  last five minutes, and raw session ids stay hashed.
- Uses five lifecycle points where the host supports them: session start, user prompt, pre-tool,
  post-tool and stop. ZCode uses its user-level `hooks.events`; DeepSeek Harness uses its Claude
  Code-compatible bridge.
- The **Agents** page separates `HOOKED`, `CONNECTED`, `VERIFIED`, `TRUST REQUIRED`, `AUDIT ONLY`
  and `DEGRADED` states. An installed hook is never presented as proof of runtime blocking.
- Agent activity is loaded from the local Blackbox audit store, with a separate bounded Axiom hook
  evidence feed. Sessions, API steps, tool calls, package installs, file access and threats can be
  filtered and copied from the UI.
- The **Verified graph sync** card mirrors the local dashboard's state machine: downloaded versus
  compiled assets, triples, verified rules and verified-answer lookup health. It draws the verified
  threat graph natively from the same local `/api/graph` data, grouped by the dashboard's categories
  and coloured by severity. **Sync now** triggers the dashboard's own `POST /api/sync`; Axiom does
  not run a second DKG sync loop. **Auto-sync** checks every 15 minutes and asks for the incremental
  catch-up only, so existing local assets stay in place and new graph entries are fetched without
  repeating the full download. Missing values stay unknown and an offline node is never shown as a
  clean graph.
- Agent configuration, sessions and databases are fingerprinted during install, hook repair and
  uninstall. Unexpected deletions or edits are reported and, where possible, restored.
- **Codex still requires its own `/hooks` trust approval.** Axiom installs the definitions but does
  not bypass, forge or pre-approve Codex trust. DeepSeek Harness also requires the official
  `@deepseek-ai/dsh-hooks-claude-code` bridge package in a DSH profile.

### Local history

- A local SQLite database stores connection metadata with UTC timestamps.
- Search by application, path, remote endpoint or PID, with time ranges from minutes to days.
- Paging, retention limits and CSV export to a path the user chooses.
- Database corruption is detected and the damaged file is preserved before a clean database is
  created.

### Firewall policy management

- Rules are path-scoped and bound to a direction and Windows network profile.
- Every rule owned by the application has a deterministic name,
  `Axiom::{rule-id}::{OUT|IN}`, so it can be found and removed without touching anyone
  else's rules.
- A rule is reported as applied only after an OS read-back of the created rule; an external block or
  Group Policy remains authoritative.
- The application never performs wildcard deletes, never resets the Windows Firewall and never
  disables Defender, BFE or another product's filters.
- Write operations stay off until consent. A **complete installation** enables **Axiom Shield**
  during setup: it registers and starts the Axiom Windows service (one administrator approval) and
  then may create or remove `Axiom::{id}::{OUT|IN}` rules. A **partial installation** leaves Shield
  off until you enable it. Every change is confirmed, read back and audited; disabling the shield
  removes every Axiom-owned rule.

### Privacy by default

- All processing is local by default. The standard build makes no outbound network call unless the
  optional AI Analyst, reputation feed or another optional module is explicitly enabled.
- No accounts, cloud sync, analytics, advertising or data sales.
- Only connection metadata is stored: no packet payload, TLS content, DNS queries, credentials or
  tokens. The optional AI evidence package adds process parent/signature/product metadata, a
  sanitised command line, a local 30-day flow baseline and host context; packet contents and
  credentials are never included.
- Optional intelligence modules (file reputation, threat feeds, DKG/Blackbox) are separate, off by
  default, and never sit on the per-connection enforcement path.

## Optional modules

The Standard build is the local monitor and firewall policy manager. Everything in this section is
an optional, separately enabled module: none of it is required, none of it starts a background
process while disabled, and none of it sits on the per-connection firewall path.

The Security page probes a running Blackbox dashboard or DKG node on loopback and reports
`CONNECTED`, `NOT RUNNING` or `UNAVAILABLE`. The Install buttons launch the official third-party
installer only after an explicit confirmation; nothing runs silently. Setup steps are in
[Optional integrations](docs/INTEGRATIONS.md).

### Privacy Shield

A local DNS filter with Basic/Balanced/Strict profiles, custom allow and block lists and a loopback
resolver. A **complete installation** turns it on with the Balanced profile and all five sources; a
partial installation leaves it off. It never changes adapter DNS settings automatically; manual
adapter configuration and rollback are documented in [Privacy Shield](docs/PRIVACY_SHIELD.md).
Five HTTPS sources are catalogued with their licenses: HaGeZi Multi PRO and OISD Big (GPL-3.0),
WindowsSpyBlocker (MIT), and The Block List Project Ads/Tracking (Unlicense). They are downloaded at
runtime, not bundled; no separate approval is required beyond the license and attribution terms.
Counters are in memory; a bounded local history of blocked domains/categories/timestamps and the
requesting application (when Windows exposes it) is kept and can be cleared. Recent blocks refresh
every 2 seconds and offer Allow/Block actions. Allowed queries are never stored. DoH/DoT/DoQ,
hardcoded IPs and VPN traffic are not covered. Optional catalogued HTTPS sources are bounded and
atomically updated; VM test coverage is tracked in
[the VM test plan](docs/PRIVACY_SHIELD_VM_TEST_PLAN.md).

### AI Security Analyst

An optional, default-disabled read-only analyst for the current bounded connection snapshot. The
primary seamless provider uses the **OpenChamber/OpenCode CLI already signed in on the PC**
(`opencode://local`), so no separate local inference server is needed; OpenAI-compatible, OpenAI,
Anthropic, DeepSeek and Z.ai providers remain available. API keys are protected with Windows DPAPI,
local paths are redacted by default and only bounded structured findings are stored. The analyst
cannot change firewall rules, execute commands or read arbitrary files. See
[AI Security Analyst](docs/AI_ANALYST.md).

### File tracker and local reputation

- Watches only the folders the user selects (for example Downloads, optionally Desktop), never the
  whole disk. The Security page also has an on-demand **Scan** action that hashes a chosen folder
  locally with SHA-256.
- Debounces file events, computes SHA-256 in the background with size and I/O limits, and reads
  Authenticode signer metadata for PE files.
- Shows local provenance, first/last seen and an explicit `unknown` result. It never uploads,
  deletes or quarantines a file automatically, and never turns an unknown hash into "malware".

### External reputation (VirusTotal gate)

- The default build sends no file, URL, hash or IP to VirusTotal.
- The Security page has a **Setup** action for an opt-in, hash-only provider. The API key is stored
  with Windows DPAPI for the current user; only a SHA-256 is sent when you press **Check**.
- The safe fallback is manual: copy the SHA-256 or open the VirusTotal website in the browser.
- A provider-neutral adapter may be added only after the concrete use is confirmed to be allowed by
  the provider. Such an adapter would be opt-in, use the user's own key, perform hash-only lookups,
  respect the published rate limits, cache results and never auto-upload files.
- A VirusTotal result is one source with a timestamp, not a verdict.

### Blackbox (Umanitek Guardian Agent Blackbox)

Blackbox is an optional local agent-safety layer. Axiom does not reimplement it: Axiom installs thin
adapters and calls the guard that Blackbox exposes from its Hermes plugin environment.

- The Blackbox dashboard and guard stay on loopback (`127.0.0.1:9700`); Axiom never opens it to the
  network. Axiom does not run Hermes, OpenClaw, Node or Docker in the background. A short-lived
  Python adapter runs only when a supported agent hook fires; if Blackbox is absent, it fails open.
- Axiom's OpenCode/Codex/Claude/ZCode/DeepSeek and other adapters send **tool and lifecycle events**
  to the local Blackbox guard. Blackbox evaluates the policy and records locally redacted audit
  events; Axiom shows those events on the Agents and Overview pages.
- In **Audit** mode Blackbox records findings without blocking. In **Block** mode it rejects
  confirmed threats according to its configured severity and policy. Axiom can switch the mode in
  `~/.hermes/config.yaml` without reinstalling.
- Agent hooks are **fail-open**: if the guard, Python runtime or hook process fails, the agent is not
  made unusable. That is a deliberate availability trade-off and is shown as `DEGRADED`, not
  "protected".
- Blackbox is third-party software. No official partnership or endorsement is implied. Codex trust
  remains a Codex-owned decision.

### OriginTrail DKG V10

OriginTrail's Decentralized Knowledge Graph (DKG) is an optional knowledge and provenance layer. It
is not a firewall engine and is not required for local monitoring or enforcement.

- The Standard build uses small, signed offline bundles; no wallet, token or local DKG node is
  required for the firewall to work.
- Advanced mode can use an already installed local Edge Node through the documented DKG
  API/CLI/MCP interface. Axiom does not start a DKG process in Standard mode.
- DKG supplies verified rules, threat context and provenance. Bundles are checked for publisher
  signature, version, expiry, revocation, replay and tampering before use.
- If the node is offline, the local firewall keeps working from the last verified cache. DKG is
  never in the per-flow firewall check.
- Signed data is evidence, not automatic truth. Publishing to a test network is a separate,
  explicit action with its own budget and approval.

**How they fit together:** Blackbox is the local **agent guard and audit trail**; DKG is the
optional **verified knowledge layer** that can supply signed rules and threat context. They are
independent: Axiom works with neither installed, a DKG outage does not disable the firewall, and an
offline Blackbox does not stop local monitoring.

### Agent security research memory

- A separate, permissively licensed package for collaborative research on public suspicious
  packages and domains; it can exist without the desktop application.
- Two or more agents use Working Memory and Shared Memory to record evidence and contradictions,
  with source, date, confidence and a `unverified`/`reviewed` status.
- It shares no secrets, wallet keys, private connection history or user paths, and it does not
  publish to a chain without an explicit later decision.

### Optional publishing, wallet protection and community reports

- TRAC / Verifiable Memory publishing is optional, starts on a test network, and requires an
  explicit budget and approval. The Standard firewall never depends on it.
- Wallet protection is a separate browser-extension research path. It never captures seed phrases
  or private keys and never signs or approves transactions.
- Community reports are opt-in and redacted. A community report never triggers automatic OS
  blocking, and a false report cannot silently block a benign site.
- The Security page has a **Setup** action for an HTTPS JSON feed. The format is
  `{"entries":[{"sha256":"...","name":"...","verdict":"...","source":"...","updatedUtc":"..."}]}`.
  Only entries with a valid SHA-256 are accepted; the feed is evidence, not a verdict.
- First-run setup can enable the bundled `axiom://starter` feed: one clearly labelled EICAR
  test entry, read from disk with no network call. Replace it with an HTTPS feed when available.

### Rules for every optional module

- Off by default: no process, account, wallet, key or network call while disabled.
- Never in the enforcement hot path; local Windows rules always apply first.
- Every finding has a source, time, confidence, expiry and a correction path; `unknown` is not
  `safe`.
- External terms (VirusTotal, Blackbox feeds, DKG, GeoIP) are reviewed before distribution.
- Integration modules keep their own permissive license and notices; no GPL-only code is copied
  into them.

## How it works

```text
Unprivileged Avalonia UI (WPF fallback retained in source)
   │  local Named Pipe (explicit ACL, client SID check)
   ▼
Windows Service
   ├─ IP Helper inventory and process attribution
   ├─ bounded aggregation and local SQLite history
   └─ owned-rule coordinator → Windows Firewall
```

- The UI never runs as administrator and never receives a generic shell or "execute" command.
- The service is the privileged boundary. It validates every request, enforces message limits and
  keeps monitoring running when the UI is closed.
- The local pipe is not reachable over SMB: network, anonymous and guest logons are denied.
- Byte accounting uses platform counters where they exist; values carry a source and a quality flag,
  and partial data is shown as partial rather than as an exact measurement.

## Security and privacy

- **Least privilege:** the UI is `asInvoker`; only the service can eventually change firewall state.
- **IPC:** explicit pipe DACL, client SID verification, typed commands, request size limit, rate
  limit, idle timeout and no generic execution endpoint.
- **Firewall safety:** only owned rules, deterministic names, read-back verification, targeted
  removal and a documented recovery path.
- **Data at rest:** per-user local database by default; only metadata; retention limits; no payload
  or secrets.
- **Honest status:** the interface distinguishes observed data, estimates, partial attribution,
  unavailable adapters and external policy conflicts. It never shows "Protected" unless the OS
  result is verified.
- **Supply chain:** pinned NuGet versions, committed lock files, warnings-as-errors and a generated
  third-party license inventory.

## Platform and requirements

- Windows 10 x64 (19041+) is the current development/test host. Windows 11 x64 uses the same
  .NET/Avalonia code path, but Windows 11 VM validation is still in the test matrix.
- .NET 10 SDK for building; the published self-contained build needs no .NET runtime.
- No administrator rights are required for the UI or for read-only console development.
- Firewall rule writes and ETW kernel tracing require an elevated service or an isolated test VM.

## Building and running

The service is built as a Windows GUI-subsystem executable, so launching it never creates a console
window. The desktop and `run-service.ps1` also start it in the background. Use the script's redirected
log when you need diagnostics.

```powershell
dotnet restore Axiom.sln --locked-mode
dotnet build Axiom.sln -c Release --no-restore
dotnet test Axiom.sln -c Release --no-build
.\scripts\publish-standalone.ps1
```

```powershell
# service mode (local history is available)
.\scripts\run-service.ps1

# in-process read-only mode
.\artifacts\publish\win-x64\Axiom.Desktop.exe
```

The standalone build produces one self-contained `Axiom.Desktop.exe` in
`artifacts\publish\win-x64`.

The legacy WPF fallback keeps software rendering enabled by default because some GPU drivers leave
the client area blank after a driver reset. Set `AXIOM_HARDWARE_RENDER=1` before starting the legacy
app to opt in to hardware acceleration on a machine where it is known to work. The Avalonia host
uses its normal platform renderer.

### Installation (no administrator)

The release ZIP contains **`Axiom-Setup.exe`**. Double-click it, choose the agent-hook scope
(Complete or Partial) and click **Install Axiom**. The setup is a single self-contained
executable with the desktop and local service payload embedded; it installs under
`%LOCALAPPDATA%\Programs\Axiom`, creates a Start Menu shortcut and starts the app. No .NET
runtime, Windows service registration, firewall change or elevation is involved.

The desktop starts the bundled local service automatically. VirusTotal remains optional; its API
key is configured later on the Security page.

**Complete installation** also runs the official Blackbox and DKG installers, starts their local
services and installs agent hooks after Blackbox is ready. Those third-party installers may download
large packages, require network access and show their own prompts/terms. **Partial installation**
installs only core Axiom and leaves Blackbox, DKG, OpenCode, OpenChamber, Codex, ZCode and DeepSeek
Harness files unchanged. Axiom also provisions Axiom-managed hooks for detected harnesses once per
build at startup, preserving user-authored hooks. Codex still requires its own one-time `/hooks`
trust review.

You can also install from a shell:

```powershell
irm https://raw.githubusercontent.com/a-51-50/Axiom/main/scripts/install-from-github.ps1 | iex
```

The bootstrap downloads the latest release, verifies `SHA256SUMS.txt`, installs under
`%LOCALAPPDATA%\Programs\Axiom` and starts the app. The first run shows the optional module
wizard.

For the private repository, authenticate with `gh auth login` first and pass the token to the
bootstrap:

```powershell
$env:AXIOM_GITHUB_TOKEN = gh auth token
$headers = @{ Authorization = "Bearer $env:AXIOM_GITHUB_TOKEN" }
irm -Headers $headers https://raw.githubusercontent.com/a-51-50/Axiom/main/scripts/install-from-github.ps1 | iex
```

The installer uses the token for release metadata and asset downloads; a public repository needs
only the plain `irm` command. A token is read from `AXIOM_GITHUB_TOKEN`, `GH_TOKEN` or
`GITHUB_TOKEN` and is never written to disk by the installer.

You can also run `.\scripts\install-portable.ps1` from a checkout. Remove with
`.\scripts\uninstall-portable.ps1`; local data stays unless `-RemoveData` is used. Details:
[`docs/INSTALL.md`](docs/INSTALL.md).

### Microsoft Store (core-only MSIX)

A core-only MSIX package can be built for Microsoft Store submission:

```powershell
.\scripts\build-msix.ps1
```

The Store signs the package, so no local code-signing certificate is needed for publication. The
package excludes the optional DKG/Blackbox installers, agent hooks and HKCU autostart. Partner
Center identity values, local test signing, submission steps and certification risks are documented
in [`docs/STORE.md`](docs/STORE.md).

## Repository layout

```text
src/
  Axiom.Contracts/              # DTOs, IPC and history contracts
  Axiom.Core/                   # domain rules and firewall port
  Axiom.Infrastructure.Windows/ # IP Helper, process identity, Named Pipe server
  Axiom.Persistence/            # SQLite schema, queries, retention
  Axiom.Service/                # Worker host, monitoring, history writer, pipe
  Axiom.Presentation/           # portable view models, state and feature services
  Axiom.UI.Avalonia/            # Avalonia views, controls, themes and host services
  Axiom.Desktop.Avalonia.Windows/ # primary Windows composition root / Axiom.Desktop.exe
  Axiom.UI/                     # WPF fallback library: views, view models, theme
  Axiom.Desktop/                # WPF fallback composition root
tests/                                  # unit and Windows integration tests
docs/                                   # architecture, security, test matrix, licensing, ADRs
scripts/                                # local run, service mode, standalone publish
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Test matrix](docs/TEST_MATRIX.md)
- [Accessibility and keyboard](docs/ACCESSIBILITY.md)
- [Performance budget](docs/PERFORMANCE_BUDGET.md)
- [Firewall recovery](docs/FIREWALL_RECOVERY.md)
- [MCP server foundation](docs/MCP.md)
- [Optional integrations](docs/INTEGRATIONS.md)
- [Licensing](docs/LICENSING.md)
- [Roadmap](docs/ROADMAP.md)
- [Architecture decision records](docs/ADR/)

## License and copyright

Copyright (C) 2026 The Axiom contributors.

Axiom is an independent open-source project affiliated with the [OpenDKG initiative](https://opendkg.org).

The desktop application, the Windows service and the core libraries are licensed under
**GNU GPL v3.0 or later**. See [`LICENSE`](LICENSE) for the full text and [`NOTICE`](NOTICE) for the
copyright and grant. Third-party components and their licenses are listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md); names and logos are covered by
[`TRADEMARKS.md`](TRADEMARKS.md). The roles of creators, copyright holders, maintainers and
contributors are described in [`AUTHORS.md`](AUTHORS.md).

The installed application shows the same information under **Settings → About Axiom**, including the
full GPL text, the notice, the third-party list and the source repository. Those documents are
embedded in the application, so they remain readable offline.

Contributions are accepted under the same license with a Developer Certificate of Origin
(`git commit -s`); see [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports go through the private
advisory process described in [`SECURITY.md`](SECURITY.md). Licensing decisions, dependency
compatibility and the rules for optional integration modules are documented in
[`docs/LICENSING.md`](docs/LICENSING.md) and
[`docs/ADR/0005-license-gpl-3.0-or-later.md`](docs/ADR/0005-license-gpl-3.0-or-later.md).
