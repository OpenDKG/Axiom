# ADR 0003 — Worker service and local Named Pipe with SID verification

- **Status:** accepted
- **Date:** 2026-11-03
- **Milestone:** FND-003
- **Builds on:** ADR 0001, ADR 0002

## Context

FND-002 read sockets in the UI process. FND-003 separates the privileged part into a Windows service
and keeps the UI unprivileged behind a local Named Pipe with an explicit ACL. No firewall write
endpoint is allowed in this phase. The definition of done requires that the UI works without admin,
that another unauthorized user cannot call the service, and that the service survives closing the UI.

The development host has no administrator rights and no VM, so service installation was not
performed. The implementation must be correct and tested as far as the environment allows, without
claiming an installed service.

## Decisions

### 1. One host runs as a Windows service and as a console process

`Host.CreateApplicationBuilder` + `AddWindowsService` (service name `LocalFirewall`). Outside SCM the
host uses the console lifetime, so development and testing need no admin. The same binary is later
installed by the installer.

### 2. Monitoring in the service, cached snapshot, thin pipe

`MonitoringWorker` polls IP Helper every second and writes a `ConnectionSnapshot` into
`ConnectionSnapshotCache`. The `snapshot` command returns the cached snapshot, so N clients do not
multiply OS calls. A revision is incremented on every successful poll.

### 3. Explicit DACL + client SID verification

- `PipeSecurity`: allow the service account (FullControl) and one authorized SID (ReadWrite); deny
  `Network`, `Anonymous`, `Guests`.
- After connect, the server reads the **client process SID** from its token
  (`GetNamedPipeClientProcessId` + process token). A mismatch closes the connection without a
  response.
- Allowed SID: `LOCALFIREWALL_ALLOWED_SID`; in console mode the current user. The installer will set
  it in FND-009.

### 4. NDJSON with hard limits and no generic commands

- One `IpcEnvelope` per line, UTF-8, max 256 KiB request; oversized messages are rejected before JSON
  parsing.
- Protocol version is validated; unknown commands return `unknown_command`.
- Implemented commands: `serviceHealth`, `capabilities`, `snapshot` (and `history.query` in FND-005).
- `rule.*`, `config.*`, `diagnostics.*`, `live.events` return `not_supported`.
- Rate limit 100 requests/s, 30 s idle, 4 instances.

### 5. Per-request UI client, no persistent state

`ServicePipeClient` connects per request (2 s connect, 5 s request timeout). Reconnect after a
service failure is therefore automatic without a state machine.

### 6. Two Desktop modes: in-process (default) and `--service`

- Default remains in-process so development and the standalone demo work without an installed
  service.
- `--service` uses the pipe and shows `Service unavailable` when the service is not reachable.
- `run-service.ps1` starts the console service and the UI with `--service`.

## Consequences

Positive:

- Clear boundary: the UI has no Windows API, the service has no UI dependency.
- IPC is tested without admin: ACL, SID rejection, limits, unsupported commands.
- The UI survives a service crash and restart; no false "live" state.

Negative / risks:

- The service is not installed; SCM behaviour, service account and installation ACL are unverified.
- A real second Windows user was not tested (only simulated through the allowed SID).
- No IPC command audit trail; required before firewall commands (FND-006).
- A cached snapshot means the UI may see data up to 1 s old; the poll time is displayed.
- No event streaming; `live.events` is deferred.

## Alternatives considered

| Alternative | Why not |
|---|---|
| UI reads IP Helper directly (FND-002 state) | No privilege separation; the service is the handoff target |
| Local HTTP API | Larger attack surface, port, CORS/auth issues; the handoff requires a pipe |
| Persistent pipe with an event stream | More complex reconnect/checkpoint; FND-004 |
| `PipeOptions.CurrentUserOnly` | A SYSTEM service could not serve the user |
| DACL for "Authenticated Users" | Too broad; violates least privilege |
| Install the service now | No admin/VM; risk of a half-verified result |
