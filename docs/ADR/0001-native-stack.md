# ADR 0001 — Native stack and FND-001 foundation

- **Status:** accepted
- **Date:** 2026-11-03
- **Milestone:** FND-001
- **Superseded in part by:** ADR 0002 (Desktop composition root)

## Context

The first milestone requires a buildable solution with clean boundaries, a WPF shell, mock
connections, two chart series, tests and CI — without installing a service, without administrator
rights, without changing Windows Firewall and without a kernel driver.

The development host is Windows 10 IoT Enterprise LTSC 2021 x64; Windows 11 x64 is the supported
target. Only the .NET runtime was installed at the time, so the SDK was installed per-user. The
application must also ship as a standalone build without a .NET runtime requirement.

## Decisions

### 1. WPF on .NET 10, not WinUI 3, Electron or Avalonia

WPF provides mature Windows integration, MVVM without an extra runtime and the lowest risk for future
COM/ETW work. Electron would add Chromium (unnecessary attack and resource surface for a local
security tool). WinUI 3 adds packaging and Windows App SDK risk. Avalonia is not needed because the
target is Windows-only.

### 2. Layered projects with enforced dependency boundaries

`Contracts`, `Core`, `Infrastructure.Windows`, `Persistence`, `Service` and `UI`, with the UI
referencing only `Contracts`. The boundary is enforced by project references, not convention.
`Core` contains no WPF, COM or P/Invoke and is testable on any platform.

### 3. Demo data isolated in the UI and explicitly labelled

The deterministic generator lives in `Netpetra.UI/Services`, uses a fixed seed and documentation
IP ranges, and is labelled `DEMO DATA`. The UI never renders an unverified "Protected" state.

### 4. No chart library in FND-001

The chart is a small `FrameworkElement` drawn with `DrawingContext`. ScottPlot is a candidate once
real data volume and interaction requirements justify the dependency (FND-004/010).

### 5. Central package versions, lock files, warnings as errors

`Directory.Packages.props` pins versions; `packages.lock.json` records the full graph; CI uses
`--locked-mode`; `TreatWarningsAsErrors` is enabled with two narrow suppressions for MVVM binding
properties and descriptive test names.

### 6. Standalone publish profile

The UI is published self-contained for `win-x64` as a single file. WPF does not support trimming, so
`PublishTrimmed` is not used. The ILLink task package is pinned so restore and publish share one
dependency graph.

### 7. No Windows Firewall access in the read-only milestones

`NotAvailableFirewallPolicyAdapter` reports `Unavailable` and throws for every operation. Rule naming
and validation are implemented and tested, but no COM call is made.

### 8. Persistence baseline without UI coupling

A SQLite bootstrap (WAL, foreign keys, `schema_migrations`, integrity check) is tested but not wired
to the UI. It becomes the base for FND-005.

## Consequences

Positive:

- Fast, deterministic builds and tests; the UI can be reviewed without network or admin rights.
- Module boundaries are mechanical, so collectors and adapters can be added safely.
- Standalone delivery is part of the build pipeline, not an afterthought.

Negative / risks:

- The demo-versus-real distinction must be removed carefully in FND-002.
- WPF single-file is not trimmed; size and startup are a trade-off.
- Windows 10 LTSC is a development host, not proof of Windows 11 behaviour.
- `RuleSpecValidator` validates address/CIDR and port scopes; the scope UI and import/export remain FND-008 work.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Electron + React | Chromium runtime, larger footprint, extra IPC layer |
| WinUI 3 + Windows App SDK | Packaging and dependency risk; less mature COM interop |
| Avalonia | Cross-platform is not a goal |
| ScottPlot immediately | Dependency without benefit for 60 demo points |
| Database before UI | FND-001 requires the shell; an empty database proves nothing |
| Service immediately | FND-003 requires the IPC security design first |
