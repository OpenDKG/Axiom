# Netpetra MCP server (foundation)

Status: **PR A foundation, read-only, not integrated into the installer.** No release, no automatic
client configuration and no firewall write tools exist in this change.

The server lets a local AI client ask what Netpetra has already observed. It is deliberately an
analyst, not an enforcement path: every tool is read-only, and the agent cannot apply a rule,
terminate a process, read an arbitrary file or run a command.

## 1. Architecture

```text
MCP client (OpenCode, another local agent)
        │  JSON-RPC over stdio, one process per client
        ▼
Netpetra.McpServer.exe
        │  existing NDJSON Named Pipe protocol
        │  \\.\pipe\Netpetra.Service.v1, DACL + client SID check
        ▼
Netpetra.Service.exe
        │  read-only IP Helper snapshot, SQLite history, rule read-back
        ▼
Windows host
```

- MCP uses **stdio**, not a network port. The client owns the child process lifetime.
- All host data comes through the existing authenticated Named Pipe. The MCP process does not open
  SQLite or Windows Firewall COM objects directly.
- The protocol is bounded by the service: 256 KiB request, 4 MiB response, 100 requests/s.
- Diagnostics from the MCP host go to **stderr**. stdout is the JSON-RPC wire.
- The server has no write tools. `netpetra_get_firewall_rules` reads capability and rules only.

## 2. Tools in PR A

| Tool | Purpose | Important limitation |
|---|---|---|
| `netpetra_get_status` | Service health, source, last capture, capabilities and limitations | A live capture is not a complete host inventory |
| `netpetra_list_connections` | Current sockets with bounded filters | Socket ownership can be unknown or `partial`; no packet contents |
| `netpetra_get_connection_history` | Stored observations with paging and real coverage | Requested range may be longer than retained history |
| `netpetra_inspect_process` | Observed executable path, PIDs, endpoints and quality | No hash, Authenticode, parent process or command line in the current IPC contract |
| `netpetra_analyze_connection` | Deterministic private/loopback/public classification and uncertainty | No reputation provider; a new public destination is a lead, not proof |
| `netpetra_get_threat_alerts` | Reports that no alert store exists yet | Empty alerts are **not** a clean bill of health |
| `netpetra_get_reputation` | Reports that no local cache/provider is configured | Unknown is not clean; no external request is sent |
| `netpetra_get_firewall_rules` | Netpetra-owned rules, capability and write-gate state | A stored rule is not proof that an observed connection was blocked |
| `netpetra_generate_security_report` | Bounded summary from stored observations | History-only; no packet, DNS, TLS or byte evidence |

All outputs include `schemaVersion`, scope/coverage and limitations. The server does not return
`SAFE`; `UNKNOWN` and `INSUFFICIENT_DATA` are valid, visible outcomes.

## 3. Security rules

- No remote transport, HTTP listener, arbitrary command execution, file browser or transcript tool.
- No tool accepts a path and reads it. Process paths are output evidence from the service, not input
  to a file operation.
- No prompts, arguments, credentials or tokens are stored or returned by this server.
- No service command has been added. The existing named-command set is unchanged.
- The server does not install or modify MCP client configuration, agent hooks, firewall rules or
  protected junctions.
- An unavailable service returns `status: "UNAVAILABLE"` with no fabricated data.
- The server must run as the same Windows user as the service's allowed SID. A mismatched SID is
  rejected by the existing pipe server.

## 4. Build and run

```powershell
dotnet build src\Netpetra.McpServer\Netpetra.McpServer.csproj -c Release
dotnet run --project src\Netpetra.McpServer
```

Then register the executable (or the `dotnet run` command) as a **local stdio MCP server** in the
client. Registration is manual in PR A; no client config is written automatically.

Smoke test used during development: initialise, list tools, call `netpetra_get_threat_alerts` and
`netpetra_get_reputation`, and call `netpetra_get_status` with the service stopped. The last call
returned `UNAVAILABLE`; the MCP process stayed alive and stdout remained valid JSON-RPC.

## 5. Testing truth

Executed:

| Check | Result |
|---|---|
| `dotnet build src\Netpetra.McpServer` | passed, 0 warnings / 0 errors |
| MCP `initialize` then `tools/list` over stdin | passed; 9 tools advertised |
| `tools/call` for unavailable status/alerts/reputation | passed; structured `UNAVAILABLE`, no crash |
| Raw JSON-RPC harness against a temporary console service | passed; status, current connections, history and report returned real observations |
| MCP unit tests (endpoint parsing, private IPv4/IPv6, indicator type, truthful unavailable states) | 32 passed |

**Not run:** a real MCP client (OpenCode/another agent) driving the tools, a model-generated
investigation, or any action against a live protected host. Those are integration checks for a
later PR and are not claimed here. The temporary service used a separate `NETPETRA_DATA_DIR` and
was stopped after the check.

## 6. Planned follow-up PRs

- **PR B: evidence and risk quality.** Add DNS/TLS/reputation evidence adapters with explicit
  provenance, freshness and false-positive handling. Keep every result read-only.
- **PR C: reports and controlled actions.** Add durable investigations/reports and a separate,
  explicit human-confirmation surface for any action. Do not expose a write tool to the model.
- **PR D: client integration and installer.** Add opt-in client registration, health diagnostics and
  per-client tests, without silently modifying agent configuration. MCP client setup remains the
  user's decision.
- **PR E: hardening.** Add pipe audit/rate telemetry for MCP calls, prompt-injection regression tests
  and a documented threat model for model output.

## 7. What this PR intentionally does not do

- It does not make AI agents "protected".
- It does not prove firewall enforcement, per-agent blocking or verified protection.
- It does not add VirusTotal, DKG or Blackbox calls to MCP.
- It does not change the Agents page, hook installation, protected junctions or existing databases.
- It does not merge or release itself.
