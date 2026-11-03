# Optional integrations

Netpetra's standard build is the local network monitor and firewall policy manager. Blackbox and
OriginTrail DKG are **optional third-party integrations**. Netpetra reads their loopback status; the
Install buttons launch the official installers only after an explicit confirmation.

Both probes accept only loopback URLs. A non-loopback endpoint is rejected, and no request leaves
the machine.

## Install buttons

The Security page has an **Install** button next to each module that is not connected. It opens a
visible PowerShell window only after a confirmation dialog:

- **DKG**: installs `@origintrail-official/dkg` into
  `%LOCALAPPDATA%\Netpetra\modules\dkg` with `--ignore-scripts`, sets a per-user `DKG_HOME`, runs
  the official interactive testnet setup (`--network testnet --role edge --store oxigraph`) and
  starts the node.
- **Blackbox**: downloads the official Umanitek Windows installer to
  `%LOCALAPPDATA%\Netpetra\modules\blackbox`, prints its SHA-256 and runs it with
  `-StoreBackend oxigraph` (no Docker).

Nothing is installed silently. Close the PowerShell window only after it reports success, then
click **Check again**. **Restart Netpetra** is available for a clean restart after installation.
The activity strip shows the last 30 loopback checks; it is a health indicator, not module event
content.

## Reputation provider (VirusTotal, opt-in)

The **Reputation provider** row has a **Setup** action. Enter your own VirusTotal API key and enable
hash-only lookups. The key is stored with Windows DPAPI for the current user and is never written in
plaintext or logged.

- Only the 64-character SHA-256 is sent to `https://www.virustotal.com/api/v3/files/{hash}`.
- Files, paths, URLs and names are never uploaded.
- A result is one source with a timestamp, not a verdict; provider rate limits and terms apply.
- Leave the key empty or disable the checkbox to keep the provider off.
- After scanning a folder, use **Check** on a row to perform the lookup.

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

Then open Netpetra -> **Security** -> **Check again**. A running node shows `CONNECTED` with its
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

Then open Netpetra -> **Security** -> **Check again**. A running dashboard shows `CONNECTED`. The
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

An **Uninstall** button appears when Netpetra detects an installed/configured module:

- **Blackbox**: stops processes whose command line points into
  `%LOCALAPPDATA%\Netpetra\modules\blackbox`, removes that folder, the
  `%USERPROFILE%\.local\bin\blackbox.cmd` shortcut, `.hermes\blackbox` and the
  `Agent Blackbox DKG node` scheduled task if present. Other Hermes profiles, logs and global
  Python/npm packages are kept.
- **DKG**: stops local processes under the Netpetra DKG folders and removes
  `%LOCALAPPDATA%\Netpetra\modules\dkg` and `dkg-home`. No global npm package is removed.
- **Reputation provider**: deletes the stored VirusTotal key and disables the provider.
- **Community feed**: deletes the stored URL/token.

The cleanup runs in a visible PowerShell window after a confirmation. It never touches Windows
Firewall rules, other applications or unrelated user data.

## Status meanings

| Status | Meaning |
|---|---|
| `CONNECTED` | The loopback endpoint answered. Netpetra only read its status. |
| `NOT RUNNING` | Nothing answered on the configured loopback endpoint. Start the module separately. |
| `UNAVAILABLE` | The endpoint is invalid or not loopback; no request was sent. |
| `CHECKING` | The initial probe is still running. |

## Security boundaries

- Install buttons launch the official installer only after explicit confirmation; nothing runs
  silently.
- Uninstall stops only processes whose command line points into the Netpetra module folder; it does
  not stop unrelated agents or global services.
- Netpetra does not configure or control a module after installation; it only reads status.
- No remote endpoint, cloud lookup, token display or credential storage.
- No DKG wallet or token is required for the status probe.
- Neither module is on the per-connection firewall enforcement path.
- A `CONNECTED` status is not a malware verdict and does not replace Windows Firewall.
