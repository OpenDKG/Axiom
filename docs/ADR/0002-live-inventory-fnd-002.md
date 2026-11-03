# ADR 0002 — Live read-only inventory through a Desktop composition root

- **Status:** accepted
- **Date:** 2026-11-03
- **Milestone:** FND-002
- **Builds on:** ADR 0001

## Context

The product must show real processes and connections. FND-002 requires an IP Helper adapter for
IPv4/IPv6 TCP/UDP, process identity, 1–2 s polling, deduplication and a live `Live Connections`
table.

The architecture rule says the UI depends only on `Contracts` and contains no Win32/COM code.
`Netrigil.UI` was an executable WPF shell, so there was no place for a Windows adapter without
breaking the boundary. In addition, .NET does not allow a self-contained executable to reference
another executable (`NETSDK1150`), and a WPF library cannot contain an `ApplicationDefinition`
(`MC1002`).

## Decisions

### 1. UI becomes a WPF library; Desktop becomes the only executable

- `Netrigil.UI` keeps views, view models, themes and the pipe client and references only
  `Contracts`.
- `Netrigil.Desktop` is the composition root: it registers the real source, builds the monitor
  and the main view model, and starts the WPF application.
- `App.xaml` (resources, data templates, theme) lives in Desktop and uses absolute pack URIs into the
  UI assembly.

**Consequence:** the dependency rule is preserved and the UI cannot compile a call to IP Helper or
the firewall. The cost is one extra project and pack URIs in `App.xaml`.

### 2. IP Helper owner tables for both families with two-call buffers

`GetExtendedTcpTable`/`GetExtendedUdpTable` with `OWNER_PID` for `AF_INET` and `AF_INET6`. Buffers are
allocated with the documented two-call pattern; rows are read with exact struct sizes
(24/56/12/28 bytes). Ports are byte-swapped; IPv4 addresses are read in network order; IPv6 uses
`IPAddress(bytes, scopeId)`.

### 3. Process identity with the minimum handle

`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageName`, cached for 30 s.
Access denied or protected processes become `unknown path` with `Partial` quality; a path is never
invented.

### 4. Direction, first-seen and quality are explicit heuristics

- IP Helper has no direction field. TCP: `Listen` or a matching local listener below the ephemeral
  range (49152) is inbound; everything else is outbound. UDP is `Unknown`.
- IP Helper has no connection start time. `FirstObservedUtc` is the first poll that saw the flow;
  `IsNew` lasts 60 s.
- Quality is `Observed` only when PID > 4 and the path is resolved; otherwise `Partial`.

### 5. PID 0 is not an application

PID 0 rows are `TIME_WAIT`/kernel leftovers. They appear in the socket table as
`System · unowned (PID 0)`, are excluded from `Apps` grouping and are counted in the summary.

### 6. One-second polling with in-place diff and live sorting

`ConnectionMonitor` polls on the UI dispatcher; `CaptureAsync` runs on the thread pool. Rows are
updated in place by key `protocol|local|remote|pid`; new rows are added and stale rows removed.
`DataGrid` sorts by `StateRank`; `Apps` uses `ListCollectionView.IsLiveSorting`.

### 7. Demo remains only for the throughput chart

Bytes are not available from the owner tables. `DemoTrafficEngine` draws a labelled `DEMO SERIES`;
`Live Connections` and `Apps` contain no demo rows. `DemoConnectionSnapshotSource` remains a design
fallback but is not registered by the published Desktop.

### 8. `netstat -ano` is the reference oracle, not `Get-Net*` cmdlets

On the test host `Get-NetTCPConnection` shows ~100 extra `Bound` rows and `Get-NetUDPEndpoint` misses
endpoints. Comparison with `netstat -ano` produced TCP 223 vs 225 and UDP 114 vs 114.

## Consequences

Positive:

- Real data without admin rights or a service; the architectural boundary is preserved.
- Deterministic integration tests for TCP/UDP and process identity.
- Standalone publishing remains a single executable.

Negative / risks:

- Poll-only misses short connections and provides no bytes.
- Paths of SYSTEM processes are often unreadable without elevation.
- Direction and first-seen are heuristics and must stay labelled.
- An extra project and pack URIs add initial WPF resource complexity.
- No persistence: a restart loses history and first-seen.

## Alternatives considered

| Alternative | Why not |
|---|---|
| UI references Infrastructure.Windows directly | Breaks the UI → Contracts rule and opens a path to firewall code from the UI |
| Service + IPC immediately | Larger security design; FND-002 is read-only |
| ETW before inventory | ETW does not provide the PID/endpoint table |
| WFP events for connections | Requires WFP subscription and privileges (FND-007) |
| Demo rows mixed with real rows | Unacceptable: the user could not tell measurement from sample |
