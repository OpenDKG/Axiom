# Netpetra

**Open-Source Firewall & Security Monitor**

**Repository:** https://github.com/a-51-50/Netpetra · **License:** GPL-3.0-or-later

Netpetra is a local, offline Windows network monitor and firewall policy manager. It shows
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
  `Netpetra::{rule-id}::{OUT|IN}`, so it can be found and removed without touching anyone
  else's rules.
- A rule is reported as applied only after an OS read-back of the created rule; an external block or
  Group Policy remains authoritative.
- The application never performs wildcard deletes, never resets the Windows Firewall and never
  disables Defender, BFE or another product's filters.
- Write operations are disabled by default. They require an explicit test-VM gate on the service and
  are audited locally; a normal install remains read-only.

### Privacy by default

- All processing is local. The standard build has no outbound network calls.
- No accounts, cloud sync, analytics, advertising or data sales.
- Only connection metadata is stored: no packet payload, TLS content, DNS queries, credentials or
  tokens.
- Optional intelligence modules (file reputation, threat feeds, DKG/Blackbox) are separate, off by
  default, and never sit on the per-connection enforcement path.

## Optional modules

The Standard build is the local monitor and firewall policy manager. Everything in this section is
an optional, separately enabled module: none of it is required, none of it starts a background
process while disabled, and none of it sits on the per-connection firewall path.

The Security page probes a running Blackbox dashboard or DKG node on loopback and reports
`CONNECTED`, `NOT RUNNING` or `UNAVAILABLE`. The Install buttons launch the official third-party
installer only after an explicit confirmation; nothing runs silently. Setup steps are in
[Optional integrations](docs/INTEGRATIONS.md).

### File tracker and local reputation

- Watches only the folders the user selects (for example Downloads, optionally Desktop), never the
  whole disk. The Security page also has an on-demand **Scan** action that hashes a chosen folder
  locally with SHA-256.
- Debounces file events, computes SHA-256 in the background with size and I/O limits, and reads
  Authenticode signer metadata for PE files.
- Shows local provenance, first/last seen and an explicit `unknown` result. It never uploads,
  deletes or quarantines a file automatically, and never turns an unknown hash into "malware".

### External reputation (VirusTotal gate)

- The default build sends no file, URL, hash or IP to VirusTotal.
- The Security page has a **Setup** action for an opt-in, hash-only provider. The API key is stored
  with Windows DPAPI for the current user; only a SHA-256 is sent when you press **Check**.
- The safe fallback is manual: copy the SHA-256 or open the VirusTotal website in the browser.
- A provider-neutral adapter may be added only after the concrete use is confirmed to be allowed by
  the provider. Such an adapter would be opt-in, use the user's own key, perform hash-only lookups,
  respect the published rate limits, cache results and never auto-upload files.
- A VirusTotal result is one source with a timestamp, not a verdict.

### Blackbox compatibility

- An adapter for an already installed Umanitek Blackbox, not a reimplementation and not a
  replacement for its configuration.
- The Standard build starts no Blackbox, Hermes, OpenClaw, Python, Node or Docker process.
- If Blackbox is not installed, the UI says `not installed`; it never claims protection from a
  component that is absent. Once installed, **Audit** and **Block** buttons switch the mode in
  `~/.hermes/config.yaml` without reinstalling.
- The difference between `audit` and `block`, and the fail-open limits of a third-party agent guard,
  are stated explicitly. No official partnership is implied.

### OriginTrail DKG V10

- The Standard build uses small, signed offline bundles; no local DKG node, wallet or token is
  required for the firewall to work.
- The Advanced mode can use an already installed local Edge Node through the documented DKG
  API/CLI/MCP interface. No DKG process is started by Standard.
- DKG is never in the per-flow firewall check. If the node is offline, the local firewall keeps
  working with the last verified cache.
- Bundles are verified for publisher signature, version, expiry, revocation, replay and tampering
  before use. Signed does not mean automatically true.

### Agent security research memory

- A separate, permissively licensed package for collaborative research on public suspicious
  packages and domains; it can exist without the desktop application.
- Two or more agents use Working Memory and Shared Memory to record evidence and contradictions,
  with source, date, confidence and a `unverified`/`reviewed` status.
- It shares no secrets, wallet keys, private connection history or user paths, and it does not
  publish to a chain without an explicit later decision.

### Optional publishing, wallet protection and community reports

- TRAC / Verifiable Memory publishing is optional, starts on a test network, and requires an
  explicit budget and approval. The Standard firewall never depends on it.
- Wallet protection is a separate browser-extension research path. It never captures seed phrases
  or private keys and never signs or approves transactions.
- Community reports are opt-in and redacted. A community report never triggers automatic OS
  blocking, and a false report cannot silently block a benign site.
- The Security page has a **Setup** action for an HTTPS JSON feed. The format is
  `{"entries":[{"sha256":"...","name":"...","verdict":"...","source":"...","updatedUtc":"..."}]}`.
  Only entries with a valid SHA-256 are accepted; the feed is evidence, not a verdict.
- First-run setup can enable the bundled `netpetra://starter` feed: one clearly labelled EICAR
  test entry, read from disk with no network call. Replace it with an HTTPS feed when available.

### Rules for every optional module

- Off by default: no process, account, wallet, key or network call while disabled.
- Never in the enforcement hot path; local Windows rules always apply first.
- Every finding has a source, time, confidence, expiry and a correction path; `unknown` is not
  `safe`.
- External terms (VirusTotal, Blackbox feeds, DKG, GeoIP) are reviewed before distribution.
- Integration modules keep their own permissive license and notices; no GPL-only code is copied
  into them.

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
dotnet restore Netpetra.sln --locked-mode
dotnet build Netpetra.sln -c Release --no-restore
dotnet test Netpetra.sln -c Release --no-build
.\scripts\publish-standalone.ps1
```

```powershell
# service mode (local history is available)
.\scripts\run-service.ps1

# in-process read-only mode
.\artifacts\publish\win-x64\Netpetra.Desktop.exe
```

The standalone build produces one self-contained `Netpetra.Desktop.exe` in
`artifacts\publish\win-x64`.

WPF software rendering is enabled by default because some GPU drivers leave the client area blank
after a driver reset. Set `NETPETRA_HARDWARE_RENDER=1` before starting the app to opt in to hardware
acceleration on a machine where it is known to work.

### Portable installation (no administrator)

```powershell
irm https://raw.githubusercontent.com/a-51-50/Netpetra/main/scripts/install-from-github.ps1 | iex
```

The bootstrap downloads the latest release, verifies `SHA256SUMS.txt`, installs under
`%LOCALAPPDATA%\Programs\Netpetra` and starts the app. The desktop starts the bundled local service
automatically; no Windows service registration, firewall change or elevation is involved. The first
run shows a setup wizard with component checkboxes, a warning and an explicit Apply/terms step.

For the private repository, authenticate with `gh auth login` first and pass the token to the
bootstrap:

```powershell
$env:NETPETRA_GITHUB_TOKEN = gh auth token
$headers = @{ Authorization = "Bearer $env:NETPETRA_GITHUB_TOKEN" }
irm -Headers $headers https://raw.githubusercontent.com/a-51-50/Netpetra/main/scripts/install-from-github.ps1 | iex
```

The installer uses the token for release metadata and asset downloads; a public repository needs
only the plain `irm` command. A token is read from `NETPETRA_GITHUB_TOKEN`, `GH_TOKEN` or
`GITHUB_TOKEN` and is never written to disk by the installer.

You can also run `.\scripts\install-portable.ps1` from a checkout. Remove with
`.\scripts\uninstall-portable.ps1`; local data stays unless `-RemoveData` is used. Details:
[`docs/INSTALL.md`](docs/INSTALL.md).

## Repository layout

```text
src/
  Netpetra.Contracts/              # DTOs, IPC and history contracts
  Netpetra.Core/                   # domain rules and firewall port
  Netpetra.Infrastructure.Windows/ # IP Helper, process identity, Named Pipe server
  Netpetra.Persistence/            # SQLite schema, queries, retention
  Netpetra.Service/                # Worker host, monitoring, history writer, pipe
  Netpetra.UI/                     # WPF library: views, view models, theme
  Netpetra.Desktop/                # composition root / the only UI executable
tests/                                  # unit and Windows integration tests
docs/                                   # architecture, security, test matrix, licensing, ADRs
scripts/                                # local run, service mode, standalone publish
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Test matrix](docs/TEST_MATRIX.md)
- [Accessibility and keyboard](docs/ACCESSIBILITY.md)
- [Performance budget](docs/PERFORMANCE_BUDGET.md)
- [Firewall recovery](docs/FIREWALL_RECOVERY.md)
- [Optional integrations](docs/INTEGRATIONS.md)
- [Licensing](docs/LICENSING.md)
- [Roadmap](docs/ROADMAP.md)
- [Architecture decision records](docs/ADR/)

## License and copyright

Copyright (C) 2026 The Netpetra/Netpetra contributors.

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
