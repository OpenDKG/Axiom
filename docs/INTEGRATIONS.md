# Optional integrations

Axiom's standard build is the local network monitor and firewall policy manager. Blackbox and
OriginTrail DKG are **optional third-party integrations**. Axiom reads their loopback status; the
Install buttons launch the official installers only after an explicit confirmation.

Both probes accept only loopback URLs. A non-loopback endpoint is rejected, and no request leaves
the machine.

The Microsoft Store MSIX build is **core-only**. It does not include these integrations, the
Blackbox/DKG installers or any agent-hook adapter. See [STORE.md](STORE.md).

Privacy Shield is a separate optional local DNS resolver; it is documented in
[PRIVACY_SHIELD.md](PRIVACY_SHIELD.md) and does not change adapter DNS automatically.

## Install buttons

The Security page has an **Install** button next to each module that is not connected. It opens a
visible PowerShell window only after a confirmation dialog:

- **DKG**: installs `@origintrail-official/dkg` into
  `%LOCALAPPDATA%\Netpetra\modules\dkg` with `--ignore-scripts`, sets a per-user `DKG_HOME`, runs
  the official interactive testnet setup (`--network testnet --role edge --store oxigraph`) and
  starts the node.
- **Blackbox**: downloads the official Umanitek Windows installer to
  `%LOCALAPPDATA%\Netpetra\modules\blackbox`, verifies its SHA-256 against the pinned digest in
  `OptionalModuleInstaller` (`261122F5E879596E88D63C30D5D36D12B4E155986F83AA3EB83ADEB406E41179`)
  and refuses to run on a mismatch, then runs it with `-StoreBackend oxigraph` (no Docker). Update
  the pin only after reviewing a new official vendor release. It then repairs the Python dependencies the dashboard
  needs (`aiohttp`, `cryptography`, `psutil`, FastAPI, uvicorn) and starts the dashboard at
  `http://127.0.0.1:9700`.

If Blackbox or DKG is installed but not running, its action changes to **Start**; it starts the
existing dashboard/node without reinstalling. The node/dashboard runs in the background, and child
console windows created by third-party launchers are hidden. The button changes to **Starting...**
and stays disabled while Axiom waits for the loopback probe; it returns to **Start** only after a
timeout or a failed launch. Nothing is installed silently. Close the PowerShell window only after
it reports success, then click **Check again**. **Restart Axiom** is available for a clean restart
after installation.
The activity strip shows the last 30 loopback checks; it is a health indicator, not module event
content.

Agent workspace labels are deliberately not interchangeable:

- **HOOKED**: the Axiom hook is installed and Blackbox is reachable, but no runtime invocation has
  been observed yet. It is shown green because the configuration and local connection are healthy.
- **CONNECTED**: the hook has produced runtime evidence and reached the local guard. End-to-end
  blocking is still not claimed unless it is explicitly verified.
- **PROTECTED**: Hermes/OpenClaw reports an attached protected workspace through Blackbox.

An installed hook is never treated as proof of runtime blocking.

### OpenCode and OpenChamber

OpenCode is protected through its native plugin API; OpenChamber uses the same
`~/.config/opencode` plugin directory. Agent hooks are **not installed automatically** when the
Blackbox dashboard connects. The single-file setup's **Complete installation** runs the official
Blackbox and DKG installers, starts both local services and then installs the hooks. On the Agents
page, choose **Install/repair agent hooks...** and select:

- **Complete installation** to add/repair the Axiom guard hooks for detected agents;
- **Partial installation** to leave every OpenCode/OpenChamber/Codex hook file unchanged.

A complete OpenCode/OpenChamber installation writes:

- `~/.config/opencode/plugins/netpetra-blackbox/index.ts`, a V2 directory plugin using
  `Plugin.define` and `ctx.tool.hook("execute.before", ...)`;
- `~/.config/opencode/plugins/netpetra-blackbox.ts`, a V1 flat-file fallback that is a no-op when
  OpenCode V2 loads it;
- `%LOCALAPPDATA%\Netpetra\modules\blackbox\agent-blackbox\netpetra-guard-bridge.py`, which calls
  Blackbox's Python guard with the tool name and arguments.

Existing Axiom-managed files are backed up beside the originals before replacement. User-authored
plugins at the same paths, reparse points/junctions and unrelated settings are never overwritten.
`IsInstalled` requires the V2 `Plugin.define`/`ctx.tool.hook` entrypoint, not just a marker string.
Status refresh remains read-only. The current Blackbox mode applies: `audit` records findings,
`block` rejects confirmed threats. Bridge or Blackbox failures fail open, like the Hermes hooks.
Restart OpenCode/OpenChamber after the first install so the plugin is loaded. Uninstalling Blackbox
removes the plugin; the bridge lives inside the Blackbox folder. This is a Axiom adapter, not an
official Blackbox attachment kind.

### Codex

Codex user hooks are read from `~/.codex/hooks.json`. Only after **Complete installation** on the
Agents page does Axiom merge a `PreToolUse` command hook and install
`netpetra-codex-hook.py` in the Blackbox folder. The existing `hooks.json` is copied to a
timestamped `.netpetra-backup-*` file before it is changed; unrelated hooks are preserved. The hook
receives Codex's `tool_name`/`tool_input`, calls the same Blackbox guard, and returns a
`permissionDecision: deny` only when Blackbox blocks. **Partial installation** leaves Codex hook
files unchanged. Codex may ask you to approve/trust the hook once; approve it and restart Codex.
Uninstalling Blackbox removes the Axiom hook entry and script.

### Claude Code

Claude Code user hooks are read from `~/.claude/settings.json`. Only after **Complete installation**
does Axiom merge a marker-owned `PreToolUse` entry and install `netpetra-claude-hook.py` in the
Blackbox folder. The existing settings file is backed up beside the original; unrelated settings and
hooks are preserved. The hook receives Claude Code's `tool_name`/`tool_input`, calls the same
Blackbox guard, and returns `hookSpecificOutput.permissionDecision: deny` only when Blackbox blocks.
**Partial installation** leaves Claude settings unchanged. Claude Code may require a hook approval
or restart; an installed hook is not proof of runtime blocking. Uninstalling Blackbox removes only
the Axiom hook entry and script.

### Cursor

Cursor user hooks are read from `~/.cursor/hooks.json`. Only after **Complete installation** does
Axiom merge a marker-owned `preToolUse` entry and install `netpetra-cursor-hook.py` in the
Blackbox folder. Existing hooks and unrelated keys are preserved; the file is backed up before a
change. The hook maps Cursor's `tool_name`/`tool_input` to the same Blackbox guard and returns
`permission: deny` only when Blackbox blocks. **Partial installation** leaves Cursor files unchanged.
Restart Cursor or reload hooks after installation; an installed hook is not proof of runtime
blocking. Uninstalling Blackbox removes only the Axiom hook entry and script.

### GitHub Copilot CLI

Copilot CLI user hooks are read from `~/.copilot/hooks/*.json`. Only after **Complete installation**
does Axiom create its own `~/.copilot/hooks/netpetra.json` and install
`netpetra-copilot-hook.py`; other hook files are never rewritten. The hook maps Copilot's
`toolName`/`toolArgs` to the Blackbox guard and returns `permissionDecision: deny` only when
Blackbox blocks. **Partial installation** leaves Copilot files unchanged. Copilot `preToolUse`
command hooks are fail-closed on crashes/non-zero exits, so the Axiom script always emits one
valid JSON decision. Restart Copilot CLI if it was already running. Uninstalling Blackbox removes
only the Axiom hook file and script.

### Gemini CLI

Gemini CLI user hooks are read from `~/.gemini/settings.json`. Axiom detects Gemini only when
that settings file exists, not merely because the shared `~/.gemini` directory is present. Complete
installation merges a marker-owned `BeforeTool` entry and installs `netpetra-gemini-hook.py`.
Unrelated settings, MCP definitions, Antigravity history/conversations and other files under
`~/.gemini` are not modified. The hook returns `decision: deny` only when Blackbox blocks; partial
installation changes nothing. Antigravity CLI may expose a different hook surface and is not assumed
to be Gemini-compatible.

### Windsurf Cascade

Windsurf user hooks are read from `~/.codeium/windsurf/hooks.json`. Complete installation merges
marker-owned entries for `pre_run_command`, `pre_write_code` and `pre_mcp_tool_use`, and installs
`netpetra-windsurf-hook.py`. Other hooks and settings are preserved. The script maps Cascade's
`tool_info` to the Blackbox guard and blocks by writing the reason to stderr and exiting with code
2; it exits 0 to allow. **Partial installation** changes nothing. Restart Cascade if it was already
running. Antigravity/Gemini history and MCP files are never touched by this adapter.

### Cline

Cline user hooks use `~/Documents/Cline/Hooks/PreToolUse.py`. Complete installation writes a
marker-owned Python hook there and never overwrites a user-authored `PreToolUse.py`; project-level
`.cline`/`.clinerules` hooks are never touched. The hook maps Cline's `tool_call.name`/`tool_call.input`
to the Blackbox guard and returns `cancel: true` with an `errorMessage` only when Blackbox blocks.
**Partial installation** changes nothing. Cline hooks must be enabled and Cline may need a restart.

### User-state protection

Installation, hook repair, complete setup and uninstall are scoped to Axiom-owned files and the
marker-owned hook entry. Before each operation Axiom fingerprints user-owned state across:

- OpenCode/OpenChamber config, credentials, sessions, projects, chats and state databases.
- Codex `config.toml`, `hooks.json`, `auth.json`, sessions, sqlite databases and state files.
- Claude, Cursor and Copilot config, credentials and session state.
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

The Agents page reads the local dashboard at `http://127.0.0.1:9700`. It never opens a public
listener and never sends data off the machine.

- **Configure** opens a native settings dialog. It reads `GET /api/settings`, edits only requested
  fields, and posts a patch to `POST /api/settings` with the per-process `X-Blackbox-Token` from
  `GET /api/session`. It then reads the settings back and verifies mode, severity, protected paths,
  detection toggles and sharing state before reporting success.
- **Protected paths** from the Blackbox settings are editable with Add file/folder/pattern and
  Remove (with confirmation). Existing defaults are preserved unless explicitly removed. These are
  Blackbox path rules, not Windows Firewall rules.
- **Agent activity** reads `GET /api/audit?limit=100&offset=0` and
  `GET /api/findings?limit=100&offset=0` every four seconds while the Overview page is selected. It
  shows recorded sessions, API calls, tool calls, package installs, file access and threats, with
  filter buttons for each category. A Security column labels each event `PASSED` (green) or
  `BLOCKED`/`FLAGGED` (red), with audit-mode flags kept distinct from actual blocks. Selecting a
  row opens a native detail pane with the session,
  tool, command/path, model/provider, package, result, duration, decision, severity and a redacted
  raw event. **Load more** raises the audit window in 100-row steps up to Blackbox's 500-row limit.
  Obvious tokens, passwords and long hex values are masked in the UI; the local dashboard may expose
  more raw data. Only an explicit `decision: block` is counted as blocked; high severity alone is not
  proof of blocking.
- **Health** reads `GET /api/graph-status`, distinguishes the dashboard's configured DKG node from
  Axiom's standalone DKG, and shows verified/community rule counts and last sync. A running
  dashboard is never presented as proof that the verified graph is synchronized.
- **Test Protection** creates a temporary harmless canary, adds it to protected paths, requires
  Block mode, calls the local guard, restores the original paths and removes the canary. Its result
  is explicitly labelled guard-level; it does not claim that an agent hook was executed.
- The OpenCode/OpenChamber/Codex rows show `HOOK INSTALLED` until a real protection test verifies
  activation; a hook file alone is not presented as `PROTECTED`. Connected/configured states
  (`HOOK INSTALLED`, `HOOK LOADED`) are green, while `AUDIT ONLY` is amber and `DEGRADED`/`OFFLINE`
  are red.

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

First-run setup can instead enable the bundled `netpetra://starter` feed. It reads
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
npm install -g @origintrail-official/dkg
dkg init
dkg start
```

Verify the node directly:

```powershell
Invoke-RestMethod http://127.0.0.1:9200/api/status
```

Then open Axiom -> **Security** -> **Check again**. A running node shows `CONNECTED` with its
version, peer id and role. The default endpoint is `http://127.0.0.1:9200`; override it only with a
loopback URL:

```powershell
$env:NETPETRA_DKG_URL = "http://127.0.0.1:9200"
```

DKG is not on the per-flow firewall path. If the node is offline, the local firewall keeps working.

Official documentation: <https://docs.origintrail.io/>

## Blackbox

Blackbox is Umanitek's runtime security product for AI agents. Follow Umanitek's official
prerequisites and review the installer before running it. The Windows installer is:

```powershell
iwr -useb blackbox-w.umanitek.ai | iex
```

The installer sets up Hermes, the Blackbox plugin and a local DKG node; the dashboard listens on
loopback at `http://127.0.0.1:9700`. Verify it directly:

```powershell
Invoke-RestMethod http://127.0.0.1:9700/api/graph-status
```

Then open Axiom -> **Security** -> **Check again**. A running dashboard shows `CONNECTED`. The
default endpoint is `http://127.0.0.1:9700`; override it only with a loopback URL:

```powershell
$env:NETPETRA_BLACKBOX_URL = "http://127.0.0.1:9700"
```

Official documentation: <https://github.com/umanitek/agent-blackbox>

## Blackbox mode

After Blackbox is installed, the Security page shows **Audit** and **Block** buttons next to it.
They update only `~/.hermes/config.yaml` -> `plugins.entries.blackbox.mode`; no reinstall or admin is
needed.

- **Audit** logs and reports findings without stopping agent actions. Recommended for first use.
- **Block** stops confirmed threats at or above the configured `block_severity` (default `critical`).
  Use it only after the ruleset is synced and false positives have been reviewed.

The current mode is shown in the Blackbox detail text. A missing config is created with `audit` as
the default when a mode is selected.

## Uninstall

An **Uninstall** button appears when Axiom detects an installed/configured module:

- **Blackbox**: stops processes whose command line points into
  `%LOCALAPPDATA%\Netpetra\modules\blackbox`, removes that folder, the
  `%USERPROFILE%\.local\bin\blackbox.cmd` shortcut, `.hermes\blackbox` and the
  `Agent Blackbox DKG node` scheduled task if present. Other Hermes profiles, logs and global
  Python/npm packages are kept.
- **DKG**: stops local processes under the Axiom DKG folders and removes
  `%LOCALAPPDATA%\Netpetra\modules\dkg` and `dkg-home`. No global npm package is removed.
- **Reputation provider**: deletes the stored VirusTotal key and disables the provider.
- **Community feed**: deletes the stored URL/token.

The cleanup runs in a visible PowerShell window after a confirmation. It never touches Windows
Firewall rules, other applications or unrelated user data.

## Status meanings

| Status | Meaning |
|---|---|
| `CONNECTED` | The loopback endpoint answered. Axiom only read its status. |
| `NOT RUNNING` | Nothing answered on the configured loopback endpoint. Start the module separately. |
| `UNAVAILABLE` | The endpoint is invalid or not loopback; no request was sent. |
| `CHECKING` | The initial probe is still running. |

## Security boundaries

- Install buttons launch the official installer only after explicit confirmation; nothing runs
  silently.
- Uninstall stops only processes whose command line points into the Axiom module folder; it does
  not stop unrelated agents or global services.
- Axiom does not configure or control a module after installation; it only reads status.
- No remote endpoint, cloud lookup, token display or credential storage.
- No DKG wallet or token is required for the status probe.
- Neither module is on the per-connection firewall enforcement path.
- A `CONNECTED` status is not a malware verdict and does not replace Windows Firewall.
