# Optional integrations

Netpetra's standard build is the local network monitor and firewall policy manager. Blackbox and
OriginTrail DKG are **optional third-party integrations**. Netpetra never installs, starts, stops or
controls them; it only reads their loopback status.

Both probes accept only loopback URLs. A non-loopback endpoint is rejected, and no request leaves
the machine.

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

## Status meanings

| Status | Meaning |
|---|---|
| `CONNECTED` | The loopback endpoint answered. Netpetra only read its status. |
| `NOT RUNNING` | Nothing answered on the configured loopback endpoint. Start the module separately. |
| `UNAVAILABLE` | The endpoint is invalid or not loopback; no request was sent. |
| `CHECKING` | The initial probe is still running. |

## Security boundaries

- No automatic installation, process start, stop or configuration.
- No remote endpoint, cloud lookup, token display or credential storage.
- No DKG wallet or token is required for the status probe.
- Neither module is on the per-connection firewall enforcement path.
- A `CONNECTED` status is not a malware verdict and does not replace Windows Firewall.
