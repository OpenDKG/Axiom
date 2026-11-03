# LocalFirewall

**Repository:** https://github.com/a-51-50/VigilMesh · **License:** GPL-3.0-or-later ·
**Working name:** LocalFirewall (repository brand: VigilMesh)

*Intelligent protection. Open by design.*

LocalFirewall is a local, offline Windows network monitor and firewall policy manager. It shows
which applications use the network, which endpoints they talk to, and what happened over time. It
manages only its own rules in the built-in Windows Firewall; Windows remains the enforcement
authority. There is no account, no cloud, no advertising and no telemetry.

## What it covers

### Per-application network visibility

- TCP and UDP sockets for IPv4 and IPv6, read from the Windows IP Helper owner tables.
- Process attribution by PID, executable name and resolved path; unresolved or protected processes
  are marked as partial instead of being guessed.
- Local and remote endpoints, connection state, direction, loopback detection and the first time a
  flow was observed.
- A sortable, filterable, virtualized table that stays responsive with hundreds of processes and
  thousands of rows.

### Local history

- A local SQLite database stores connection metadata with UTC timestamps.
- Search by application, path, remote endpoint or PID, with time ranges from minutes to days.
- Paging, retention limits and CSV export to a path the user chooses.
- Database corruption is detected and the damaged file is preserved before a clean database is
  created.

### Firewall policy management

- Rules are path-scoped and bound to a direction and Windows network profile.
- Every rule owned by the application has a deterministic name,
  `LocalFirewall::{rule-id}::{OUT|IN}`, so it can be found and removed without touching anyone
  else's rules.
- A rule is reported as applied only after an OS read-back of the created rule; an external block or
  Group Policy remains authoritative.
- The application never performs wildcard deletes, never resets the Windows Firewall and never
  disables Defender, BFE or another product's filters.

### Privacy by default

- All processing is local. The standard build has no outbound network calls.
- No accounts, cloud sync, analytics, advertising or data sales.
- Only connection metadata is stored: no packet payload, TLS content, DNS queries, credentials or
  tokens.
- Optional intelligence modules (file reputation, threat feeds, DKG/Blackbox) are separate, off by
  default, and never sit on the per-connection enforcement path.

## How it works

```text
Unprivileged WPF UI
   │  local Named Pipe (explicit ACL, client SID check)
   ▼
Windows Service
   ├─ IP Helper inventory and process attribution
   ├─ bounded aggregation and local SQLite history
   └─ owned-rule coordinator → Windows Firewall
```

- The UI never runs as administrator and never receives a generic shell or "execute" command.
- The service is the privileged boundary. It validates every request, enforces message limits and
  keeps monitoring running when the UI is closed.
- The local pipe is not reachable over SMB: network, anonymous and guest logons are denied.
- Byte accounting uses platform counters where they exist; values carry a source and a quality flag,
  and partial data is shown as partial rather than as an exact measurement.

## Security and privacy

- **Least privilege:** the UI is `asInvoker`; only the service can eventually change firewall state.
- **IPC:** explicit pipe DACL, client SID verification, typed commands, request size limit, rate
  limit, idle timeout and no generic execution endpoint.
- **Firewall safety:** only owned rules, deterministic names, read-back verification, targeted
  removal and a documented recovery path.
- **Data at rest:** per-user local database by default; only metadata; retention limits; no payload
  or secrets.
- **Honest status:** the interface distinguishes observed data, estimates, partial attribution,
  unavailable adapters and external policy conflicts. It never shows "Protected" unless the OS
  result is verified.
- **Supply chain:** pinned NuGet versions, committed lock files, warnings-as-errors and a generated
  third-party license inventory.

## Platform and requirements

- Windows 11 x64 is the supported target. Windows 10 x64 is best-effort.
- .NET 10 SDK for building; the published self-contained build needs no .NET runtime.
- No administrator rights are required for the UI or for read-only console development.
- Firewall rule writes and ETW kernel tracing require an elevated service or an isolated test VM.

## Building and running

```powershell
dotnet restore LocalFirewall.sln --locked-mode
dotnet build LocalFirewall.sln -c Release --no-restore
dotnet test LocalFirewall.sln -c Release --no-build
.\scripts\publish-standalone.ps1
```

```powershell
# service mode (local history is available)
.\scripts\run-service.ps1

# in-process read-only mode
.\artifacts\publish\win-x64\LocalFirewall.Desktop.exe
```

The standalone build produces one self-contained `LocalFirewall.Desktop.exe` in
`artifacts\publish\win-x64`.

## Repository layout

```text
src/
  LocalFirewall.Contracts/              # DTOs, IPC and history contracts
  LocalFirewall.Core/                   # domain rules and firewall port
  LocalFirewall.Infrastructure.Windows/ # IP Helper, process identity, Named Pipe server
  LocalFirewall.Persistence/            # SQLite schema, queries, retention
  LocalFirewall.Service/                # Worker host, monitoring, history writer, pipe
  LocalFirewall.UI/                     # WPF library: views, view models, theme
  LocalFirewall.Desktop/                # composition root / the only UI executable
tests/                                  # unit and Windows integration tests
docs/                                   # architecture, security, test matrix, licensing, ADRs
scripts/                                # local run, service mode, standalone publish
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Test matrix](docs/TEST_MATRIX.md)
- [Licensing](docs/LICENSING.md)
- [Roadmap](docs/ROADMAP.md)
- [Architecture decision records](docs/ADR/)

## License and copyright

Copyright (C) 2026 The VigilMesh/LocalFirewall contributors.

The desktop application, the Windows service and the core libraries are licensed under
**GNU GPL v3.0 or later**. See [`LICENSE`](LICENSE) for the full text and [`NOTICE`](NOTICE) for the
copyright and grant. Third-party components and their licenses are listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md); names and logos are covered by
[`TRADEMARKS.md`](TRADEMARKS.md).

Contributions are accepted under the same license with a Developer Certificate of Origin
(`git commit -s`); see [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports go through the private
advisory process described in [`SECURITY.md`](SECURITY.md). Licensing decisions, dependency
compatibility and the rules for optional integration modules are documented in
[`docs/LICENSING.md`](docs/LICENSING.md) and
[`docs/ADR/0005-license-gpl-3.0-or-later.md`](docs/ADR/0005-license-gpl-3.0-or-later.md).
