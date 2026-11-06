# Security model — Axiom (FND-005)

## 1. Current trust boundary

| Process | Rights | What it does |
|---|---|---|
| `Netpetra.Desktop.exe` | `asInvoker` | UI; reads IP Helper or calls the pipe |
| `Netpetra.Service.exe` | `asInvoker` (console mode) | polls IP Helper, writes SQLite, serves the pipe |
| `Netpetra.McpServer.exe` | `asInvoker`, same user | read-only MCP tools; calls the authenticated pipe only |

In production the service would run under a service account (FND-009); the UI stays unprivileged.
There are no COM/WFP/ETW/netsh calls, no firewall writes and no outbound network communication.

ETW (FND-004) is not implemented; when it arrives it requires `SeSystemProfilePrivilege` and belongs
in the service.

## 2. Named Pipe protection

- `\\.\pipe\Netpetra.Service.v1`.
- Explicit DACL: allow the service account + one SID; deny `Network`/`Anonymous`/`Guests`.
- The client process SID is read from its token after connect; a mismatch closes the connection.
- Limits: request 256 KiB, response 4 MiB, 100 requests/s, 30 s idle, 4 instances.
- Named commands only; no `exec`; firewall writes/config/diagnostics/`live.events` →
  `not_supported` (`history.query` and read-only `rules.query` are supported).
- Errors return a code and message, without a stack trace.
- The MCP adapter uses the same DACL/SID-checked pipe. It has no direct database, firewall COM,
  registry or filesystem API, and exposes no write tool.

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
- Failed or throwing removals are also audited as `rule.remove` / `failed`; the stored rule is
  marked `Failed` instead of remaining `Applied`.
- Reapplying a rule clears a removed port scope, and read-back/verification compares action,
  direction, protocol, profiles, enabled state, addresses and ports against the persisted spec.
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
| Malicious prompt induces MCP tool abuse | Read-only tools only; no path input, shell, exec, rule or config command | PR A; no model-driven adversarial test yet |
| MCP process reads data directly | Pipe-only adapter; no SQLite/COM/registry access | Code review; service SID check remains |

## 6. Limitations and checks not run

- The service is not installed (no admin/VM); the console host and pipe were tested.
- A real second Windows account was not tested; ACL/SID rejection were.
- No installation ACL or signing (FND-009).
- No IPC command audit trail; required before firewall commands (FND-006). MCP calls are therefore
  not separately audited yet.
- No real MCP client or prompt-injection exercise has been run; only raw JSON-RPC and unit tests.
- ETW/bytes are not implemented; FND-004 requires elevation.
- The database is not encrypted; data is per-user metadata. This is a decision for FND-009.

## 7. Microsoft Store (MSIX) mode

The Store package is core-only. At process start the Desktop host asks Windows for package identity
and sets `DistributionContext.IsStorePackage`. In that mode:

- DKG/Blackbox module entries and the Agents page are hidden;
- optional installer/uninstaller methods return without launching PowerShell;
- agent hook installation and hook probes are disabled;
- HKCU `Run` autostart is disabled; Store packages use package activation instead;
- no optional module file or agent configuration is created or removed.

The package is a full-trust MSIX with `runFullTrust`, `internetClient` and
`privateNetworkClientServer`. It is unsigned locally and signed by Microsoft during Store
submission. See [STORE.md](STORE.md).

## 8. Privacy Shield (FND-020, initial local resolver)

- Disabled by default; enabling is an explicit UI action. The service itself never changes adapter
  DNS, the hosts file, firewall state or agent configuration. A separate explicit UAC helper can
  change one selected adapter after the user approves Windows elevation.
- The resolver binds UDP and TCP loopback only (`127.0.0.1`, and `::1` when available). It is not a
  LAN resolver. TCP is used for TCP queries and oversized/truncated UDP fallback.
- Blocked queries are answered locally with NXDOMAIN. Allowed queries are forwarded to the current
  Windows DNS servers or an explicitly configured non-loopback upstream.
- Only catalogued HTTPS blocklist sources are downloadable. Updates are bounded to 20 MB/45 s,
  validated, normalized and atomically swapped; the previous ruleset is retained for rollback.
- The policy engine evaluates only the DNS question name. It does not inspect payloads, TLS, HTTP
  or application identity and does not claim per-process DNS attribution.
- Counters and top blocked domains are in memory. A bounded, local blocked-query history (last 1,000)
  stores only blocked domain, category and timestamp in
  `%LOCALAPPDATA%\Netpetra\privacy-shield-blocked.jsonl`; allowed queries are never stored, and the
  user can clear it. No other DNS history is written to SQLite or any other store.
- If no non-loopback system DNS is available, the service uses a conservative public fallback
  (`1.1.1.1`/`9.9.9.9`) and reports it, so a manually configured loopback adapter does not lose all
  resolution. Managed networks should set an explicit upstream.
- DoH/DoT/DoQ, hardcoded IPs, VPN tunnels and pre-activation cache bypass the resolver. A blocked
  query is not evidence that a connection was prevented.
- See [PRIVACY_SHIELD.md](PRIVACY_SHIELD.md) for the user-facing safety and recovery contract.

## 9. AI Security Analyst (FND-019 initial manual mode)

- Disabled by default. The AI page is a manual action; it does not auto-analyze network events in
  this build.
- The API key is DPAPI-protected for the current user. Findings contain structured summaries and
  evidence references, not prompts, provider responses or keys.
- Evidence is bounded to process metadata, endpoints, direction, state and quality. Local paths are
  reduced to file names by default. Packet contents, credentials, cookies, agent histories and
  arbitrary files are never collected.
- Cloud endpoints require HTTPS; HTTP is accepted only for a loopback local endpoint.
- Provider output is treated as untrusted. It is parsed into a fixed structured contract, list
  lengths are bounded, `SAFE`/`CLEAN` are normalized to `UNKNOWN`, and no firewall, shell, file or
  agent-config action field exists.
- A model warning is not a confirmed incident, and `SUPPORTED_ALERT` is not an enforcement result.
- The existing MCP server remains read-only and separate; this initial UI path does not add a second
  MCP server or any MCP write tool.

## 10. Reporting vulnerabilities

Until a public channel exists, report directly to the project owner. Do not publish real SIDs,
paths or database content in a reproduction.
