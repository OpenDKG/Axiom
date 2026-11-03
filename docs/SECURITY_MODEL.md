# Security model — Netpetra (FND-005)

## 1. Current trust boundary

| Process | Rights | What it does |
|---|---|---|
| `Netpetra.Desktop.exe` | `asInvoker` | UI; reads IP Helper or calls the pipe |
| `Netpetra.Service.exe` | `asInvoker` (console mode) | polls IP Helper, writes SQLite, serves the pipe |

In production the service would run under a service account (FND-009); the UI stays unprivileged.
There are no COM/WFP/ETW/netsh calls, no firewall writes and no outbound network communication.

ETW (FND-004) is not implemented; when it arrives it requires `SeSystemProfilePrivilege` and belongs
in the service.

## 2. Named Pipe protection

- `\\.\pipe\Netpetra.Service.v1`.
- Explicit DACL: allow the service account + one SID; deny `Network`/`Anonymous`/`Guests`.
- The client process SID is read from its token after connect; a mismatch closes the connection.
- Limits: request 256 KiB, response 4 MiB, 100 requests/s, 30 s idle, 4 instances.
- Named commands only; no `exec`; firewall/history/config/diagnostics/`live.events` →
  `not_supported` (`history.query` is supported).
- Errors return a code and message, without a stack trace.

## 3. Data at rest (FND-005)

- Database: `%LOCALAPPDATA%\Netpetra\netpetra.db` (per-user/console mode) or
  `%ProgramData%\Netpetra\` (installed service). `NETPETRA_DATA_DIR` overrides the path.
- Only **connection metadata** is stored: process name/path, PID, protocol, local/remote endpoint,
  state, direction, quality, first/last seen.
- No payload, TLS content, DNS queries, tokens or credentials are stored.
- Retention: 30 days; old flows and apps without flows are deleted.
- SQLite WAL; `foreign_keys=ON`; `integrity_check` at startup.
- A corrupt file is moved to `.corrupt-<timestamp>` (not deleted) and the database is recreated.
- CSV export writes to a path the user explicitly selects; UTF-8 BOM; escaping.
- The installer (FND-009) must set an explicit ACL on `%ProgramData%\Netpetra\`; development
  uses per-user LocalAppData.

## 4. Firewall write gate (FND-006)

- `WindowsFirewallPolicyAdapter` uses the documented COM policy/rule objects on a dedicated STA
  thread. Read-only listing and verification are enabled; writes are gated.
- Both variables must be present on the service process: `NETPETRA_ENABLE_FIREWALL_WRITES=1` and
  `NETPETRA_FIREWALL_WRITE_CONFIRM=yes`. A normal build starts with both unset.
- Only exact `Netpetra::{id}::{OUT|IN}` names are created or removed; no wildcard, prefix or group
  deletion exists.
- The coordinator writes pending/applied/failed state and an audit row (actor SID, time, action,
  result, spec, error) in the same SQLite transaction as the rule state.
- The UI disables block/remove unless the service reports `FirewallWrites=true`.
- The development host has not had any rule applied. Real enforcement, external-rule conflicts and
  rollback remain VM checks (ADR 0007).

## 5. Threat model

| Threat | FND-005 | Control |
|---|---|---|
| Another local user calls the service | DACL + SID check | Foreign SID rejection tested |
| Remote pipe access | Deny `Network`/`Anonymous`/`Guests` | Local pipe |
| Reading someone else's history | Per-user LocalAppData; ProgramData ACL in FND-009 | Per-user path |
| Sensitive content in the database | Only metadata | No payload/DNS |
| Oversized response / DoS | 4 MiB response cap, 256 KiB request, 100/s | Buffered reader + limits |
| Corrupt database | `integrity_check` + `.corrupt-*` backup | Tested |
| Unbounded database growth | 30-day retention, hourly check | Tested |
| SQL injection through search | Parameterized queries + `LIKE ... ESCAPE` | Tested |
| Fake PID/path | `partial`, `unknown path` | FND-010 |
| Firewall change | No write commands | FND-006 |
| Service crash | UI `Service unavailable`, reconnect | E2E tested |

## 6. Limitations and checks not run

- The service is not installed (no admin/VM); the console host and pipe were tested.
- A real second Windows account was not tested; ACL/SID rejection were.
- No installation ACL or signing (FND-009).
- No IPC command audit trail; required before firewall commands (FND-006).
- ETW/bytes are not implemented; FND-004 requires elevation.
- The database is not encrypted; data is per-user metadata. This is a decision for FND-009.

## 7. Reporting vulnerabilities

Until a public channel exists, report directly to the project owner. Do not publish real SIDs,
paths or database content in a reproduction.
