# ADR 0004 — Local SQLite history and the FND-004 deferral

- **Status:** accepted
- **Date:** 2026-11-03
- **Milestone:** FND-005 (FND-004 deferred)
- **Builds on:** ADR 0001–0003

## Context

The next milestone in the handoff is FND-004 (ETW byte accounting). An ETW kernel network session
requires `SeSystemProfilePrivilege`. The development process is UAC-filtered: `BUILTIN\Administrators`
is deny-only, `whoami /priv` does not list `SeSystemProfilePrivilege`, and
`logman create trace -p Microsoft-Windows-Kernel-Network` returns **Access is denied**. No VM or
elevated session is available to the agent.

Implementing ETW without being able to verify event IDs, fields and byte semantics would violate the
handoff rule against inventing ETW fields. FND-004 is therefore deferred, and FND-005 (history) is
implemented because it is fully verifiable without elevation and does not depend on bytes.

## Decisions

### 1. SQLite schema v1 with `flows` and `apps`

Tables: `schema_migrations`, `apps`, `flows`, `traffic_buckets`, `settings`. A flow is unique by
`(app_id, protocol, local_endpoint, remote_endpoint, process_id)`. `first_seen_utc` is preserved;
`last_seen_utc`, `state`, `direction` and `quality` are updated.

**Consequence:** repeated polls do not duplicate rows; history grows only with new flows.

### 2. Batch writes every 2 s, not per poll

`HistoryWriter` takes the latest snapshot from the cache and writes it in one transaction every two
seconds. Retention runs at startup and hourly.

**Consequence:** ~30 writes per minute instead of 60+; WAL stays small. The UI still gets 1 s
freshness through the pipe; history is up to 2 s behind.

### 3. UTC in storage, local time in the UI

All time columns are ISO-8601 UTC strings (`O`), so lexicographic ordering and ranges are correct.
The UI converts to local time for display only.

**Consequence:** DST and time-zone changes do not corrupt queries.

### 4. History only through the service

The UI does not reference `Persistence`; `history.query` goes over the pipe. In in-process mode the
`History` page states that the service is required.

**Consequence:** one source of truth for the database and no SQLite file locked by the UI.

### 5. 30-day retention and corrupt-database recovery

Default retention is 30 days; flows older than the boundary and apps without flows are deleted. If
`integrity_check` fails or SQLite reports "not a database", the file is moved to
`.corrupt-<timestamp>` and the database is recreated. Nothing is silently deleted.

### 6. Separate request and response limits

The NDJSON request limit stays 256 KiB; responses may be up to 4 MiB. A snapshot with 3000 sockets is
~1.5 MB and legitimately exceeds the request limit. The reader is buffered (16 KiB), not byte-by-byte.

**Consequence:** large snapshots work; the `Snapshot_larger_than_the_request_limit_is_returned` test
guards against regression. The 4 MiB cap still requires pagination for extreme hosts in the future.

### 7. PID 0 and unknown paths are stored as they are

Rows with PID 0 (`TIME_WAIT`/kernel) and unreadable paths are stored with `quality=Partial` and an
app key derived from the PID. No application is invented.

**Consequence:** history is truthful but may contain many `System · unowned (PID 0)` rows; this is
visible in the UI and searchable.

### 8. CSV export from the UI

The UI requests up to 5000 rows with the current filter and writes CSV to a user-selected path
(UTF-8 BOM, escaping). No new IPC file endpoint is added.

**Consequence:** the service gets no right to write outside its database; export is an explicit user
action.

## Consequences

Positive:

- Real, searchable history that survives a service restart (verified: 4229 flows after restart).
- Every FND-005 requirement is verifiable without admin (except the CSV dialog).
- The database is per-user in development; the installer adds a ProgramData ACL.

Negative / risks:

- FND-004 remains undone; the chart is demo and there are no bytes.
- The database grows with unique flows; 30-day retention is fixed in code.
- No database encryption; metadata (paths, endpoints) is stored, not content.
- CSV export is limited to 5000 rows per action.
- `traffic_buckets` is an empty table until FND-004.

## Alternatives considered

| Alternative | Why not |
|---|---|
| ETW now, without verification | Forbidden by the handoff; unverified byte semantics |
| In-memory history | Does not survive restart; FND-005 DoD fails |
| CSV as the primary store | No queries, indexes or retention |
| Write every poll | Unnecessary WAL load |
| Database in the UI process | Breaks the UI → Contracts boundary |
| Snapshot pagination now | Larger protocol; 4 MiB covers real cases |
