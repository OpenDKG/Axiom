# Axiom architecture — current Windows implementation

**Applies to:** development version 0.10.23. **Primary desktop:** Avalonia; the WPF desktop remains in the repository as a legacy fallback. This document describes runtime boundaries rather than the early FND-005 design proposal.

## System diagram

~~~text
 Axiom.Desktop.exe (Avalonia, unprivileged)
   |  typed local IPC over an authenticated Windows Named Pipe
   v
 Axiom.Service.exe (Windows service for Axiom Shield; per-user service path for basic monitoring)
   +-- IP Helper socket inventory, process attribution and measured counters
   +-- bounded SQLite network/throughput history and Axiom-owned firewall audit
   +-- Privacy Shield: local loopback DNS proxy, disk-backed compiled block lists
   +-- threat-sharing preview queue (no service-side publication)
   +-- firewall policy coordinator -> Windows Firewall (Axiom:: owned rules only)

 Optional components outside the firewall/connection enforcement path:
   Axiom UI -- local HTTP --> Blackbox dashboard/guard at 127.0.0.1:9700
                                     |
                           local audit / verified graph cache
                                     |
                                 DKG node and network peers
   Axiom UI -- local HTTP --> standalone DKG status at 127.0.0.1:9200
   User-approved report -- Blackbox CLI --> community graph
   AI Analyst -- explicit provider or signed-in OpenCode CLI --> findings only
   MCP server -- stdio + authenticated Named Pipe --> read-only Axiom service
~~~

Blackbox's *configured* DKG node and Axiom's *standalone* DKG node must be treated as distinct until identity/configuration proves otherwise. A successful localhost probe does not establish remote connectivity or current graph synchronization.

## Current projects

| Project | Responsibility |
|---|---|
| `Axiom.Contracts` | Shared types, IPC, local security contracts, module status |
| `Axiom.Core` | Domain logic and firewall policy interfaces |
| `Axiom.Infrastructure.Windows` | Windows IP Helper/process identity and Windows-specific plumbing |
| `Axiom.Persistence` | SQLite history, storage and migrations |
| `Axiom.Service` | Monitoring, Privilege boundary, Privacy Shield, firewall coordinator, local queue |
| `Axiom.Presentation` | Portable view-model, settings and optional integration logic |
| `Axiom.UI.Avalonia` | Current Avalonia pages, navigation, themes and native dialogs |
| `Axiom.Desktop.Avalonia.Windows` | Primary Windows executable composition root |
| `Axiom.UI`, `Axiom.Desktop` | Legacy WPF UI and fallback desktop retained in source |
| `Axiom.McpServer` | Separate read-only stdio MCP adapter, not an authorization path for writes |

Avalonia provides UI portability; Windows socket inventory, service integration, Windows Firewall and adapter-DNS operations are **not** automatically portable to Linux or macOS. See [cross-platform handoff](CROSS_PLATFORM_UI_HANDOFF.md).

## Runtime privilege model

- The Avalonia UI runs as the signed-in user; it must not silently elevate or make direct privileged firewall changes.
- Axiom Shield requires user consent and the installed Windows service for Windows Firewall writes. The service runs as `LocalSystem` with restricted installation/data ACLs. It manages only rule names of the `Axiom::{id}::{OUT|IN}` form, with read-back verification and audit.
- The basic portable app can monitor without registering a privileged Windows service. This mode does **not** imply that firewall writes are available.
- An explicit UAC helper may update the selected Windows DNS adapter after approval; the local resolver itself does not silently change adapter DNS.
- Optional DKG/Blackbox installers, agent-hook setup and third-party processes have distinct permissions and terms. They are not part of Windows Firewall's enforcement process.

## IPC and storage

The UI talks to the service over `\\.\pipe\Axiom.Service.v1`: NDJSON messages with bounded request/response sizes, explicit DACL and client-SID validation, typed commands and rate limits. External network clients cannot use the pipe as a remote management API. The MCP adapter also uses the pipe and exposes read-only tools; it does not read SQLite or invoke Windows Firewall COM directly.

Axiom stores its own network observations and settings locally, including retained SQLite flow/throughput history, firewall rule/audit records, bounded blocked-DNS history, AI findings and the threat-sharing preview queue. Different stores have different retention limits. Blackbox/Hermes maintains **its own** local guard/audit/profile data and reporter key. Do not conflate Blackbox data with Axiom's SQLite history; see [security model](SECURITY_MODEL.md).

## Monitoring and firewall behaviour

The service uses Windows IP Helper socket owner tables and counters. Ownership can be partial or unknown; it is not packet capture and does not prove full connection contents. Live activity and historical samples are presented with data-quality flags and gaps rather than invented per-process traffic.

Windows Firewall enforces Axiom-owned rules, including when the desktop closes. No DKG lookup or cloud API call occurs on the per-connection enforcement path. Turning Axiom Shield off removes Axiom-owned rules; service outages do not by themselves remove already-applied Windows rules. See [firewall recovery](FIREWALL_RECOVERY.md).

## Privacy Shield DNS behaviour

Privacy Shield is a local DNS proxy, not an inline packet firewall or network gateway. Blocked names receive NXDOMAIN when queries reach its resolver; allowed queries are forwarded to the configured upstream DNS. The source catalog includes telemetry, ad, tracking and dedicated malware lists, with local rule compilation and rollback on failed updates. Applications using their own DoH, direct IPs, VPN resolvers or cached answers may bypass this layer.

The explicit adapter helper stores previous DNS servers. It places a real fallback behind the loopback resolver where possible; the service has a restore failsafe for disable/stop/start failure. **If fallback DNS takes over, internet name resolution may recover while Privacy Shield filtering is bypassed.** Never describe resolver failure as guaranteed continuous protection.

See [Privacy Shield](PRIVACY_SHIELD.md) for current configuration, recovery and limitations.

## Blackbox and DKG integration

The Blackbox dashboard is accessed over local loopback. Agent hooks send lifecycle/tool events to the local guard; their true blocking status depends on the active mode, host integration and a functioning guard. If the guard fails, hooks are designed to fail open; `DEGRADED` is not `PROTECTED`.

Axiom displays the Blackbox verified graph using the local dashboard API, and can ask the dashboard to synchronize. Optional auto-sync is **off by default**; when enabled it requests incremental updates about every 15 minutes. Existing local cached state can remain visible offline but must show its last-known status.

Axiom can queue and offer approved, signed IOC reports through the Blackbox CLI. No service background timer silently publishes them. **Community reports, verified graph data and Windows Firewall rules are separate concepts.** Axiom does not currently issue paid VM publications or turn community reports directly into OS blocks.

See [threat intelligence](THREAT_INTELLIGENCE.md) and [optional integrations](INTEGRATIONS.md).

## Release modes, operational limitations and tests

- **Portable/Standard:** local monitoring, firewall management subject to Shield setup, Privacy Shield and local features; optional modules are not required.
- **Complete installation:** explicitly selected installation/configuration of Blackbox, DKG and selected agent hooks, possibly involving downloads, separate prompts and privileges.
- **Microsoft Store MSIX:** core-only package with optional module installers and agent hooks excluded; see [Store](STORE.md).
- **Development limitations:** ETW per-process byte-level telemetry is not complete; some per-agent runtime integrations depend on external host behaviour and tests; unsigned portable releases can trigger Windows SmartScreen.
- **Runtime truth:** health status, hook installed status, graph synchronized status and proven block status must be distinct. No green badge should be inferred merely from a file, listener or report existing.

Historical FND documents and Avalonia migration matrices are planning/baseline records and should not be treated as the current implementation contract. For tests, compare the versioned [test matrix](TEST_MATRIX.md) and [release notes](RELEASES/0.10.23.md).