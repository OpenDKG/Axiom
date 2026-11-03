# Architecture — Netrigil (FND-005)

Current state: read-only inventory in the service, a local Named Pipe, SQLite history, and a UI that
runs either in-process or through the service. FND-004 (ETW bytes) is deferred because it requires
elevation.

## 1. Context

```text
┌────────────────────────────────────────────────────────┐
│ Netrigil.Desktop (WinExe, asInvoker)              │
│ chooses the source: in-process or service              │
└───────────────┬────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────┐
│ Netrigil.UI (WPF library, Contracts only)         │
│ Live/Apps/History/Overview · ConnectionMonitor         │
└───────┬──────────────────────────────┬─────────────────┘
        │ IConnectionSnapshotSource    │ ServicePipeClient
┌───────▼──────────────────┐    ┌──────▼──────────────────────┐
│ Infrastructure.Windows   │    │ \\.\pipe\Netrigil.…    │
│ IP Helper · process      │    └──────┬──────────────────────┘
│ identity · PipeServer    │           │
└──────────────────────────┘    ┌──────▼──────────────────────┐
                                │ Netrigil.Service       │
                                │ MonitoringWorker → cache    │
                                │ HistoryWriter → SQLite      │
                                │ PipeServerWorker            │
                                └──────┬──────────────────────┘
                                       │
                                ┌──────▼──────────────────────┐
                                │ Persistence (HistoryStore)  │
                                │ WAL · migrations · retention│
                                └─────────────────────────────┘
```

## 2. Projects and dependencies

| Project | Depends on | Responsibility |
|---|---|---|
| Contracts | — | DTOs, IPC, history contract, `IConnectionSnapshotSource` |
| Core | Contracts | domain rules, firewall port |
| Infrastructure.Windows | Contracts, Core | IP Helper, process identity, Named Pipe server |
| Persistence | Contracts | SQLite schema, upsert, query, retention |
| Service | Contracts, Core, Infrastructure, Persistence | host, monitoring, history writer, pipe |
| UI | **Contracts only** | Views/ViewModels/theme, pipe client |
| Desktop | UI, Infrastructure | composition root / the only EXE |

`UI` has no Windows reference; `System.IO.Pipes` is BCL. Windows API code lives in
Infrastructure/Service/Desktop.

## 3. Service

- `MonitoringWorker`: IP Helper every 1 s → `ConnectionSnapshotCache` (volatile reference + revision).
- `HistoryWriter`: writes the latest snapshot to SQLite every 2 s; retention at startup and hourly.
- `PipeServerWorker`: pipe with an explicit DACL, SID check and limits.
- `ServiceInfo`: start time is set explicitly (`MarkStarted`) so uptime does not depend on lazy type
  initialization.

## 4. IPC

- NDJSON, one `IpcEnvelope` per line.
- Request max **256 KiB**; response max **4 MiB** (a snapshot with thousands of sockets exceeds the
  request limit).
- Buffered `IpcLineReader` (16 KiB reads, growing output) — no byte-by-byte reading.
- Commands: `serviceHealth`, `capabilities`, `snapshot`, `history.query`.
- `rule.*`, `config.*`, `diagnostics.*`, `live.events` → `not_supported`.
- DACL: allow the service account + one SID; deny `Network`/`Anonymous`/`Guests`; the client SID is
  read from the process token after connect.

## 5. SQLite history (FND-005)

- Path: `NETRIGIL_DATA_DIR` → otherwise `%LOCALAPPDATA%` (interactive process) or
  `%ProgramData%` (service).
- WAL, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`.
- Tables:
  - `schema_migrations(version, applied_utc, checksum)` — version 1,
  - `apps(id, app_key UNIQUE, display_name, executable_path, first_seen_utc, last_seen_utc)`,
  - `flows(id, app_id, process_id, protocol, local_endpoint, remote_endpoint, direction, state,
    quality, first_seen_utc, last_seen_utc, UNIQUE(app_id, protocol, local, remote, pid))`,
  - `traffic_buckets` — prepared for FND-004, not filled yet,
  - `settings`.
- Upsert: `first_seen` is preserved; `last_seen`, `state`, `direction`, `quality` are updated.
- Query: UTC range, search (name/path/remote/PID), `LIMIT/OFFSET`, `COUNT(*)` for the total.
- Retention: 30 days; deletes old `flows` and `apps` without flows.
- Corrupt database: `integrity_check`/SQLite 26 → `ClearAllPools`, file moved to `.corrupt-<ts>`,
  recreate.
- Indexes: `last_seen_utc`, `remote_endpoint`, `app_id`.

## 6. UI

- Navigation follows the V2 set: Overview, Connections, Applications, Events, Firewall, Files,
  Security, Settings.
- `ConnectionMonitor`: 1 s polling, keyed diff, raises `Updated` on success and on error (offline
  banner).
- `Connections` includes an explicit `COUNTRY` placeholder. No GeoIP database is loaded, so every
  row shows an unknown country instead of inferring a flag from an IP address.
- `Applications` groups observed executables by resolved path with live sorting by socket count.
- `Events` is a unified timeline. Network events come from the service database; `Blocked`, `Files`,
  `Agents` and `System` are present as filters but report that no events of that type exist in this
  build.
- `Files` and `Security` are gated pages: they list planned scope and disabled optional modules
  instead of showing a fake scanner, feed or agent connection.
- `HistoryViewModel`/`Alerts` were replaced by `EventsViewModel`; the database still stores flows.
- The throughput chart is still a demo series (`DEMO SERIES`) with three labelled demo event
  markers; real markers and bytes are FND-010/FND-004.

## 7. Deferred

- **FND-004 (ETW)**: a kernel network session requires `SeSystemProfilePrivilege`; this session is
  UAC-filtered (`logman` → Access denied). Implementation and verification move to an elevated
  session/VM.
- FND-006 firewall writes, FND-007 alerts, FND-009 installer/signing.
- Service account and installation ACL; filling `traffic_buckets`.

Decisions: ADR 0001–0006.
