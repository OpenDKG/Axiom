# Optional integrations

Axiom's standard build is the local network monitor and firewall policy manager. Blackbox and
OriginTrail DKG are **optional third-party integrations**. Axiom checks their local loopback status,
can explicitly install/start the modules and provides a Blackbox settings/sync/report interface.
These operations require the user's choice or a separately enabled auto-sync preference; none of
them is on the per-connection firewall enforcement path.

Both **status probes** accept only loopback URLs; a non-loopback module endpoint is rejected.
This does not mean the third-party node, its package installer, sync or approved report submission
is offline-only: those components may communicate with peers or external endpoints.

The Microsoft Store MSIX build is **core-only**. It does not include these integrations, the
Blackbox/DKG installers or any agent-hook adapter. See [STORE.md](STORE.md).

Privacy Shield is a separate optional local DNS resolver; it is documented in
[PRIVACY_SHIELD.md](PRIVACY_SHIELD.md) and does not change adapter DNS automatically.

## Install buttons

The Security page has an **Install** button next to each module that is not connected. It opens a
visible PowerShell window only after a confirmation dialog:

- **DKG**: installs the pinned `@origintrail-official/dkg@10.1.0` (the testnet tag, not npm's
  mainnet `latest`) into `%LOCALAPPDATA%\Axiom\modules\dkg` with `npm ci` from the embedded
  `package-lock.json`, sets a per-user `DKG_HOME`, runs the official interactive testnet setup
  (`--network testnet --role edge --store oxigraph`), disables the package's five-minute
  auto-updater, and starts the node. An existing Axiom-managed install with another version is
  stopped and upgraded.
- **Blackbox**: downloads the official Umanitek Windows installer to
  `%LOCALAPPDATA%\Axiom\modules\blackbox`, verifies its SHA-256 against the pinned digest in
  `OptionalModuleInstaller` (`261122F5E879596E88D63C30D5D36D12B4E155986F83AA3EB83ADEB406E41179`)
  and refuses to run on a mismatch, then runs it with `-StoreBackend oxigraph` (no Docker). Update
  the pin only after reviewing a new official vendor release. It then repairs the Python dependencies the dashboard
  needs (`aiohttp`, `cryptography`, `psutil`, FastAPI, uvicorn) and starts the dashboard at
  `http://127.0.0.1:9700`. The status probe only treats the dashboard as connected when
  `/api/graph-status` returns `mode`, `node_reachable`, `dkg_url` and `sync_progress`; another
  listener on 9700 is reported as `UNKNOWN`.

If Blackbox or DKG is installed but not running, its action changes to **Start**; it starts the
existing dashboard/node without reinstalling. The node/dashboard runs in the background, and child
console windows created by third-party launchers are hidden. The button changes to **Starting...**
and stays disabled while Axiom waits for the loopback probe; it returns to **Start** only after a
timeout or a failed launch. Nothing is installed silently. Close the PowerShell window only after
it reports success, then click **Check again**. **Restart Axiom** is available for a clean restart
after installation.
The activity strip shows the last 30 loopback checks; it is a health indicator, not module event
content. The Agents page also shows a **Threat sharing** card that reads the dashboard's `report`
setting (`off · opt in` or `on · signed, redacted`) and can enable or disable signed, redacted
community sharing after confirmation. Only privacy-safe indicators are queued; prompts, commands,
file paths, credentials, model content and raw session ids are never sent. A queued indicator is
signed and sent only when the user presses **Share** on it or **Send now** for the queue — Axiom
never sends on a timer. A timeout, missing CLI or offline node marks the item **deferred** with a
retry time instead of rejecting it; a daily cap leaves it pending for the next day. Only an explicit
schema or policy refusal is recorded as rejected.

The card also shows which Hermes profile the reporter uses and whether its consent and
`reporter_key.pem` are present. Axiom resolves the profile once: `HERMES_HOME` when set, then
`%LOCALAPPDATA%\hermes`, then the legacy `~\.hermes`. `BLACKBOX_HOME` overrides the Blackbox folder
inside it.

Agent workspace labels are deliberately not interchangeable:

- **HOOKED**: the Axiom hook is installed and Blackbox is reachable, but no recent runtime
  invocation has been observed. Evidence older than five minutes is not treated as live.
- **CONNECTED**: the hook has produced recent runtime evidence and reached the local guard.
  End-to-end blocking is still not claimed unless it is explicitly verified.
- **TRUST REQUIRED**: Codex has the hook definitions, but its own `/hooks` review has not trusted
  the current hashes. Axiom never writes Codex trust state.
- **AUDIT ONLY**: runtime evidence exists, but Blackbox is in `audit` mode; the hook observes
  rather than blocks.
- **VERIFIED**: a guard-level canary test returned a block. The real host process was not
  exercised unless a host-level test is explicitly documented.
- **PROTECTED**: Hermes/OpenClaw reports an attached protected workspace through Blackbox.

An installed hook is never treated as proof of runtime blocking. Agent executables are also
discovered on `PATH`, so an installed host is detected even before it creates its config directory.

### OpenCode and OpenChamber

OpenCode is protected through its native plugin API; OpenChamber uses the same
`~/.config/opencode` plugin directory. Axiom provisions Axiom-managed hooks for every detected
harness **once per build at startup**; no second setup dialog is required. Existing user-authored
hooks and unrelated settings are preserved, and Codex still owns its `/hooks` trust decision.
The setup's **Complete installation** still runs the official Blackbox and DKG installers and
starts both local services. On the Agents page, **Install/repair agent hooks...** remains available
to repair immediately or to choose:

- **Complete installation** to add/repair the Axiom guard hooks for detected agents;
- **Partial installation** to leave every OpenCode/OpenChamber/Codex/ZCode/DeepSeek hook file unchanged.

A complete OpenCode/OpenChamber installation writes:

- `~/.config/opencode/plugins/axiom-blackbox/index.ts`, a V2 directory plugin using
  `Plugin.define` and `ctx.tool.hook("execute.before", ...)`;
- `~/.config/opencode/plugins/axiom-blackbox.ts`, a V1 flat-file fallback that is a no-op when
  OpenCode V2 loads it;
- `%LOCALAPPDATA%\Axiom\modules\blackbox\agent-blackbox\axiom-guard-bridge.py`, which calls
  Blackbox's Python guard with the tool name and arguments.

The plugin also observes OpenCode's native `/api/event` stream using the local server port and
password. It emits a session-start event on the first observed session, a pre-API-request event on
each `session.step.started`, and a session-end event when a session is deleted. This fills the
Sessions and API-call categories without reading prompts, messages, paths or file contents. A
process-wide guard prevents the V1 fallback and V2 directory plugin from registering twice.

Existing Axiom-managed files are backed up beside the originals before replacement. User-authored
plugins at the same paths, reparse points/junctions and unrelated settings are never overwritten.
`IsInstalled` requires the V2 `Plugin.define`/`ctx.tool.hook` entrypoint, not just a marker string.
Status refresh remains read-only. The current Blackbox mode applies: `audit` records findings,
`block` rejects confirmed threats. Bridge or Blackbox failures fail open, like the Hermes hooks.
Restart OpenCode/OpenChamber after the first install so the plugin is loaded. Uninstalling Blackbox
removes the plugin; the bridge lives inside the Blackbox folder. This is an Axiom adapter, not an
official Blackbox attachment kind.

### Codex

Codex user hooks are read from `~/.codex/hooks.json`. After **Complete installation** on the
Agents page, Axiom merges the full lifecycle set: `SessionStart`, `UserPromptSubmit`,
`PreToolUse`, `PostToolUse` and `Stop`. The existing file is backed up to a timestamped
`.axiom-backup-*` file; unrelated hooks are preserved. Each handler has a 30 second timeout and
passes its framework/workspace identity to the same Blackbox guard. `apply_patch` input is
normalised so the target path is visible to file-access rules.

Codex still requires its own trust review. The Agents page reads Codex's `config.toml` hook-state
hashes and reports **TRUST REQUIRED** until every current lifecycle definition is trusted. Open
Codex, run `/hooks`, trust the Axiom hooks and restart Codex. Changing the hook command or bridge
version invalidates trust again. Axiom never edits Codex's trust state or bypasses its review.
**Partial installation** leaves Codex hook files unchanged. Uninstalling Blackbox removes the Axiom
hook entries and script.

### Claude Code

Claude Code user hooks are read from `~/.claude/settings.json`. After **Complete installation**,
Axiom merges marker-owned `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse` and `Stop`
entries and installs `axiom-claude-hook.py` in the Blackbox folder. The existing settings file is
backed up beside the original; unrelated settings and hooks are preserved. The hook passes prompt
and tool-call events to the same Blackbox guard with a 30 second timeout, normalises `apply_patch`
targets and returns `hookSpecificOutput.permissionDecision: deny` only on a block.
**Partial installation** leaves Claude settings unchanged. Claude Code may require a hook approval
or restart; an installed hook is not proof of runtime blocking. Uninstalling Blackbox removes only
the Axiom hook entries and script.

### Host sessions

The Agents and Agent Stats pages read Claude's live session descriptors, Codex's local
`state_*.sqlite` thread metadata and OpenCode/OpenChamber's read-only `opencode.db` (`session_v2`)
rows, group them by provider and show host-owned names instead of submitted prompts. A session is
marked **live** when its host process is running or its data changed within the last five minutes;
older rows are historical, not errors. Raw session ids are hashed before they reach the view model.
The reader is read-only, bounded and fail-open; missing or locked host data never blocks hook
installation or protection status.

### Cursor

Cursor user hooks are read from `~/.cursor/hooks.json`. Only after **Complete installation** does
Axiom merge a marker-owned `preToolUse` entry and install `axiom-cursor-hook.py` in the
Blackbox folder. Existing hooks and unrelated keys are preserved; the file is backed up before a
change. The hook maps Cursor's `tool_name`/`tool_input` to the same Blackbox guard and returns
`permission: deny` only when Blackbox blocks. **Partial installation** leaves Cursor files unchanged.
Restart Cursor or reload hooks after installation; an installed hook is not proof of runtime
blocking. Uninstalling Blackbox removes only the Axiom hook entry and script.

### GitHub Copilot CLI

Copilot CLI user hooks are read from `~/.copilot/hooks/*.json`. Only after **Complete installation**
does Axiom create its own `~/.copilot/hooks/axiom.json` and install
`axiom-copilot-hook.py`; other hook files are never rewritten. The hook maps Copilot's
`toolName`/`toolArgs` to the Blackbox guard and returns `permissionDecision: deny` only when
Blackbox blocks. **Partial installation** leaves Copilot files unchanged. Copilot `preToolUse`
command hooks are fail-closed on crashes/non-zero exits, so the Axiom script always emits one
valid JSON decision. Restart Copilot CLI if it was already running. Uninstalling Blackbox removes
only the Axiom hook file and script.

### Gemini CLI

Gemini CLI user hooks are read from `~/.gemini/settings.json`. Axiom detects Gemini only when
that settings file exists, not merely because the shared `~/.gemini` directory is present. Complete
installation merges a marker-owned `BeforeTool` entry and installs `axiom-gemini-hook.py`.
Unrelated settings, MCP definitions, Antigravity history/conversations and other files under
`~/.gemini` are not modified. The hook returns `decision: deny` only when Blackbox blocks; partial
installation changes nothing. Antigravity CLI may expose a different hook surface and is not assumed
to be Gemini-compatible.

### Windsurf Cascade

Windsurf user hooks are read from `~/.codeium/windsurf/hooks.json`. Complete installation merges
marker-owned entries for `pre_run_command`, `pre_write_code` and `pre_mcp_tool_use`, and installs
`axiom-windsurf-hook.py`. Other hooks and settings are preserved. The script maps Cascade's
`tool_info` to the Blackbox guard and blocks by writing the reason to stderr and exiting with code
2; it exits 0 to allow. **Partial installation** changes nothing. Restart Cascade if it was already
running. Antigravity/Gemini history and MCP files are never touched by this adapter.

### Cline

Cline user hooks use `~/Documents/Cline/Hooks/PreToolUse.py`. Complete installation writes a
marker-owned Python hook there and never overwrites a user-authored `PreToolUse.py`; project-level
`.cline`/`.clinerules` hooks are never touched. The hook maps Cline's `tool_call.name`/`tool_call.input`
to the Blackbox guard and returns `cancel: true` with an `errorMessage` only when Blackbox blocks.
**Partial installation** changes nothing. Cline hooks must be enabled and Cline may need a restart.

### ZCode

ZCode user hooks live in `~/.zcode/cli/config.json` under `hooks.events`. Axiom sets
`hooks.enabled: true`, preserves unrelated hooks and keys, and adds the five lifecycle handlers
(`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`) as `process` hooks that
invoke `axiom-zcode-hook.py`. ZCode ignores project-level hook configuration; Axiom never writes
project `.zcode` or `zcode.json` files. Restart ZCode or start a new session after installation
because ZCode snapshots hooks at session start. **Partial installation** changes nothing.

### DeepSeek Harness (DSH)

DeepSeek Harness does not read a hook file by itself. Axiom writes the Claude-compatible lifecycle
file to `~/.dsh/axiom-hooks.json` and adds one managed row to `~/.dsh/cordis.patch.yml` mounting
DeepSeek's `@deepseek-ai/dsh-hooks-claude-code` bridge at that absolute path. Existing hooks and
patch rows are preserved. The Agents page reports `DETECTED` until the bridge package is installed
in a DSH profile; Axiom does not install or upgrade npm packages automatically. Once the bridge is
present, restart DSH. The file uses the same five lifecycle events and the
`axiom-deepseek-hook.py` adapter. **Partial installation** changes nothing.

### User-state protection

Installation, hook repair, complete setup and uninstall are scoped to Axiom-owned files and the
marker-owned hook entry. Before each operation Axiom fingerprints user-owned state across:

- OpenCode/OpenChamber config, credentials, sessions, projects, chats and state databases.
- Codex `config.toml`, `hooks.json`, `auth.json`, sessions, sqlite databases and state files.
- Claude, Cursor and Copilot config, credentials and session state.
- ZCode user configuration/instructions and DeepSeek Harness hook/config/profile state.
- Hermes config, memories, skills, tools, hooks, pairing data and sessions.
- Gemini and Antigravity config, MCP files, conversations, brain, cache and history databases.
- Axiom theme, tray, reputation, community and onboarding settings.

Small files are hashed and can be restored byte-for-byte. Large agent databases are fingerprinted
by length and last-write time so a multi-gigabyte database is never loaded or rehashed during every
action; small session/history files are hashed. Junctions and reparse points are recorded and never
traversed; install and uninstall cleanup refuses to recurse through a reparse point. Unexpected
changes are restored where possible; setup stops if restoration fails and
uninstall reports any path it could not restore. Uninstall deletes an OpenCode plugin only when it
contains the `Managed by Axiom` marker, and leaves Codex `hooks.json` byte-identical when no
Axiom hook is present.

Complete installation shows the exact paths and hook entry it may write. The official Blackbox/DKG
installers are allowed to change only their documented Axiom module paths and the Hermes plugin
config/mode files; any other protected change is treated as out of scope. Hermes YAML is edited with
a line-preserving editor that changes only `plugins.entries.blackbox.mode`, so comments, key order
and quoting survive the mode update. Axiom does not write Codex `config.toml`.

## Blackbox control center

The Agents page reads the local dashboard at `http://127.0.0.1:9700`. Axiom does not open a
public API listener; **dashboard API calls remain on loopback**, while a user-requested graph
sync or approved reporter submission may cause the separate Blackbox/DKG components to contact
external peers. The local-only API boundary must not be confused with network-silent integration.

- **Configure** opens a native settings dialog. It reads `GET /api/settings`, edits only requested
  fields, and posts a patch to `POST /api/settings` with the per-process `X-Blackbox-Token` from
  `GET /api/session`. It then reads the settings back and verifies mode, severity, protected paths,
  detection toggles and sharing state before reporting success.
- **Protected paths** from the Blackbox settings are editable with Add file/folder/pattern and
  Remove (with confirmation). Existing defaults are preserved unless explicitly removed. These are
  Blackbox path rules, not Windows Firewall rules.
- **Agent activity** loads the complete local audit history in 500-row pages when the Overview page
  is selected (bounded at 20,000 rows), then merges the newest page periodically. It shows recorded
  sessions, API calls, tool calls, package installs, file access and threats, with filter buttons for
  each category. Counts are therefore all-time, not just the newest page; **Load more** remains only
  for histories above the bound. A Security column labels each event `PASSED` (green) or
  `BLOCKED`/`FLAGGED` (red), with audit-mode flags kept distinct from actual blocks. Selecting a
  row opens a native detail pane with the session,
  tool, command/path, model/provider, package, result, duration, decision, severity and a redacted
  raw event. Right-click copies the selected event, all details or the raw redacted JSON; individual
  detail values, findings, hook evidence, agents and host sessions also expose copy actions.
  Obvious tokens, passwords and long hex values are masked in the UI; the local dashboard may expose
  more raw data. Only an explicit `decision: block` is counted as blocked; high severity alone is not
  proof of blocking.
- **Health** reads `GET /api/graph-status`, distinguishes the dashboard's configured DKG node from
  Axiom's standalone DKG, and shows verified/community rule counts and last sync. A running
  dashboard is never presented as proof that the verified graph is synchronized.
- **Verified graph sync** reads `GET /api/verified-sync` and `GET /api/graph?tier=public` from the
  local dashboard. The card shows the server-owned state (`synced`, `syncing`, `node offline`,
  `unknown`), downloaded versus compiled assets, triples, verified rules and verified-answer lookup
  health. The native graph view groups the first loaded verified threats by the dashboard's
  categories and uses severity rings, so it does not need a WebView or a second browser process.
  `Sync now` sends `POST /api/sync` with the `X-Blackbox-Token` from `GET /api/session`; Axiom does
  not start a second DKG sync loop. When the dashboard is busy with a long node read, Axiom falls
  back to the local `authoritative-sync.json`, `sync_progress.json` and `ruleset.json` files for the
  last known counts and graph sample instead of falsely reporting the node offline. Null values are
  shown as `—`, never as zero, and an offline node is never presented as an empty or clean graph.
  **Auto-sync is opt-in and off by default**; when enabled, Axiom asks the local dashboard for
  incremental catch-up approximately every 15 minutes. A graph drawn from the local fallback files
  is last-known state, not proof of a new remote verification.
- **Test Protection** creates a temporary harmless canary, adds it to protected paths, requires
  Block mode, calls the local guard, restores the original paths and removes the canary. Its result
  is explicitly labelled guard-level; it does not claim that an agent hook was executed.
- The OpenCode/OpenChamber/Codex rows show `HOOK INSTALLED` until a real protection test verifies
  activation; a hook file alone is not presented as `PROTECTED`. Connected/configured states
  (`HOOK INSTALLED`, `HOOK LOADED`) are green, while `AUDIT ONLY` is amber and `DEGRADED`/`OFFLINE`
  are red.

For the complete IOC lifecycle, SWM/VM distinctions, local retry semantics, upstream curation,
provenance and paid VM publishing boundaries, see [Threat intelligence](THREAT_INTELLIGENCE.md).
Axiom currently does not directly pay TRAC/gas or publish VM assets.

## Reputation provider (VirusTotal, opt-in)

The **Reputation provider** row has a **Setup** action. Enter your own VirusTotal API key and enable
hash-only lookups. The key is stored with Windows DPAPI for the current user and is never written in
plaintext or logged.

- Only the 64-character SHA-256 is sent to `https://www.virustotal.com/api/v3/files/{hash}`.
- Files, paths, URLs and names are never uploaded.
- A result is one source with a timestamp, not a verdict; provider rate limits and terms apply.
- Leave the key empty or disable the checkbox to keep the provider off.
- After scanning a folder, use **Check** on a row to perform the lookup.

The Community feed card provides **Test feed** (validates the configured URL/token and reports the entry count without replacing the visible list) and **Refresh feed** (fetches and replaces the visible entries). Neither action uploads local files, paths or connection data.

## Community feed (opt-in)

The **Community feed** row has a **Setup** action. Enter an HTTPS URL and an optional bearer token;
the token is stored with Windows DPAPI. The feed is evidence, not a verdict.

First-run setup can instead enable the bundled `axiom://starter` feed. It reads
`community/feed.json` next to the executable, contains one clearly labelled EICAR test entry and
makes no network call. Replace it with an HTTPS source when one is available; the starter feed is
not live threat intelligence.

```json
{
  "entries": [
    {
      "sha256": "64-char-hex",
      "name": "optional display name",
      "verdict": "optional provider label",
      "source": "optional source",
      "updatedUtc": "optional ISO-8601 timestamp"
    }
  ]
}
```

Only entries with a valid 64-character SHA-256 are accepted. **Refresh feed** fetches the configured
URL; nothing is published and no local path or connection data is sent.

## OriginTrail DKG V10

Requirements: Node.js and npm, per the official DKG V10 documentation.

```powershell
npm install -g @origintrail-official/dkg@10.1.0
dkg init --network testnet --role edge --store oxigraph
dkg start
```

Axiom's own installer pins the same testnet release in a lockfile and turns off the node's
auto-updater; a global install follows npm's tags and is the user's own choice.

Verify the node directly:

```powershell
Invoke-RestMethod http://127.0.0.1:9200/api/status
```

Then open Axiom -> **Security** -> **Check again**. A running node shows `CONNECTED` with its
version, peer id, role and network. The probe only accepts the documented `/api/status` identity
fields and a known testnet/mainnet `networkId`; any other listener on 9200 is reported as
`UNKNOWN`, not connected. The default endpoint is `http://127.0.0.1:9200`; override it only with a
loopback URL:

```powershell
$env:AXIOM_DKG_URL = "http://127.0.0.1:9200"
```

DKG is not on the per-flow firewall path. If the node is offline, the local firewall keeps working.

Official documentation: <https://docs.origintrail.io/>

## Blackbox

Blackbox is Umanitek's runtime security product for AI agents. Follow Umanitek's official
prerequisites and review the installer before running it. The Windows installer is:

```powershell
iwr -useb https://blackbox-w.umanitek.ai | iex
```

The installer sets up Hermes, the Blackbox plugin and a local DKG node; the dashboard listens on
loopback at `http://127.0.0.1:9700`. Verify it directly:

```powershell
Invoke-RestMethod http://127.0.0.1:9700/api/graph-status
```

Then open Axiom -> **Security** -> **Check again**. A running dashboard shows `CONNECTED`. The
default endpoint is `http://127.0.0.1:9700`; override it only with a loopback URL:

```powershell
$env:AXIOM_BLACKBOX_URL = "http://127.0.0.1:9700"
```

Official documentation: <https://github.com/umanitek/agent-blackbox>

## Blackbox mode

After Blackbox is installed, the Security page shows **Audit** and **Block** buttons next to it.
They update only `plugins.entries.blackbox.mode` in the resolved Hermes profile's `config.yaml`
(`HERMES_HOME`, then `%LOCALAPPDATA%\hermes`, then `~\.hermes`); no reinstall or admin is needed.

- **Audit** logs and reports findings without stopping agent actions. Recommended for first use.
- **Block** stops confirmed threats at or above the configured `block_severity` (default `critical`).
  Use it only after the ruleset is synced and false positives have been reviewed.

The current mode is shown in the Blackbox detail text. A missing config is created with `audit` as
the default when a mode is selected.

## Uninstall

An **Uninstall** button appears when Axiom detects an installed/configured module:

- **Blackbox**: stops processes whose command line points into
  `%LOCALAPPDATA%\Axiom\modules\blackbox`, removes that folder, the
  `%USERPROFILE%\.local\bin\blackbox.cmd` shortcut, the resolved Blackbox home (usually
  `%LOCALAPPDATA%\hermes\blackbox`, or `~\.hermes\blackbox` on legacy profiles) and the
  `Agent Blackbox DKG node` scheduled task if present. Other Hermes profiles, logs and global
  Python/npm packages are kept.
- **DKG**: stops local processes under the Axiom DKG folders and removes
  `%LOCALAPPDATA%\Axiom\modules\dkg` and `dkg-home`. No global npm package is removed.
- **Reputation provider**: deletes the stored VirusTotal key and disables the provider.
- **Community feed**: deletes the stored URL/token.

The cleanup runs in a visible PowerShell window after a confirmation. It never touches Windows
Firewall rules, other applications or unrelated user data.

## Status meanings

| Status | Meaning |
|---|---|
| `CONNECTED` | An expected local module identity/status payload was returned; does **not** prove fresh graph sync or active agent blocking. |
| `NOT RUNNING` | The configured local endpoint did not answer. Use the explicit Start action if installed. |
| `UNKNOWN` | A listener answered but did not identify as the expected module. |
| `UNAVAILABLE` | An invalid/non-loopback module endpoint was rejected; no probe was sent. |
| `CHECKING` | The initial probe is still running. |

Graph sync has separate `synced`, `syncing`, `node offline` and `unknown` states; a hook has
separate installed, loaded, audited and confirmed-blocked states.

## Security boundaries

- Install buttons launch the official installer only after explicit confirmation; nothing runs
  silently.
- Uninstall stops only processes whose command line points into the Axiom module folder; it does
  not stop unrelated agents or global services.
- Axiom can explicitly configure Blackbox settings/mode, trigger a local-dashboard sync,
  start an installed module and run user-approved reporter submissions. It does **not** silently
  write third-party agent configurations outside its documented marker-owned adapters.
- Local status probes are loopback-only, but selected feeds, AI providers, VirusTotal and the
  underlying DKG/Blackbox components can access external endpoints when enabled.
- Axiom stores selected opt-in provider/feed credentials using DPAPI, while Blackbox has its own
  local profile, signing identity and consent files. A local status probe alone does not require a
  DKG wallet.
- No DKG wallet or token is required for the status probe.
- Neither module is on the per-connection firewall enforcement path.
- A `CONNECTED` status is not a malware verdict and does not replace Windows Firewall.
