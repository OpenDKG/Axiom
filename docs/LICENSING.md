# Licensing

## Decision

The desktop application, the Windows service and the core libraries are licensed under
**GNU General Public License v3.0 or later** (`GPL-3.0-or-later`).

- Full text: [`LICENSE`](../LICENSE)
- Copyright and grant: [`NOTICE`](../NOTICE)
- Third-party components: [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)
- Names and logos: [`TRADEMARKS.md`](../TRADEMARKS.md)

The project is free of charge, without accounts, ads, paid tiers or telemetry. GPL-3.0-or-later
keeps derivative distributions open while allowing anyone to distribute the software, including
commercially, as long as the license terms are respected. It does not prevent third parties from
charging for installation, support or hosting.

## SPDX

Source files carry:

```text
SPDX-License-Identifier: GPL-3.0-or-later
```

When adding a new source file, include the same identifier. Do not remove existing copyright or
SPDX lines.

## Dependency compatibility

All pinned NuGet dependencies are MIT or Apache-2.0, which are compatible with GPL-3.0-or-later:

- MIT: CommunityToolkit.Mvvm, Microsoft.Data.Sqlite, Microsoft.Extensions.*, Microsoft.NET.Test.Sdk,
  Microsoft.NET.ILLink.Tasks.
- Apache-2.0: SQLitePCLRaw.*, xunit.*.
- The .NET 10 runtime redistributed by the self-contained build is MIT.

The exact versions and licenses are generated from `packages.lock.json` into
`THIRD_PARTY_NOTICES.md`. Update that file whenever the locked graph changes.

Apache-2.0 code is compatible with GPLv3 (patent and notice terms), but **not** with GPLv2. Do not
downgrade the project license to GPLv2 without a full dependency review.

## Optional integration modules

Modules under `integrations/` (for example the future agent-security-memory package) are separate
works and may use **MIT or Apache-2.0** so they can be consumed by other ecosystems and registries.
Rules:

- No GPL-3.0-only code may be copied into an MIT/Apache-2.0 module.
- Each module keeps its own `LICENSE`, `NOTICE` and third-party notices.
- The GPL desktop/service may reference a permissively licensed module, but the module must not
  depend on GPL-only code.
- Shared protocol/schema definitions should live in `Netrigil.Contracts` under GPL-3.0-or-later
  unless they are deliberately extracted into a permissive package with maintainer approval.

## Reference projects and third-party products

GlassWire, simplewall (GPL-3.0), Portmaster (GPL-3.0), ScottPlot (MIT), PerfView/TraceEvent (MIT) and
similar projects are **references**, not code sources. No code has been copied from them. If code is
ever imported:

- record the exact commit/version and license,
- keep required notices and copyright lines,
- verify compatibility with GPL-3.0-or-later,
- update `THIRD_PARTY_NOTICES.md` and this document.

GPL code from simplewall/Portmaster may be used in the GPL-3.0-or-later application only with
attribution and a license review; it must never be copied into an MIT/Apache-2.0 integration module.

## External services and data

- VirusTotal integration is not enabled by default; the public API has usage limits and terms that
  must be reviewed before any distribution. No automatic upload or lookup exists in the current
  build.
- Blackbox is MIT, but its feeds and hosted components may have separate terms. No feed
  redistribution without review.
- OriginTrail DKG integration is optional and separate; no token, wallet or node is required for the
  Standard build.
- GeoIP databases, if added, need a license that allows redistribution in this project.

## Release obligations

When distributing binaries:

- include or link to the complete corresponding source for the GPL-covered work,
- keep `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`,
- state any modifications,
- do not imply official status for unofficial builds (see `TRADEMARKS.md`).

## Legal review

This document records an engineering decision, not legal advice. A legal/license review is required
before the first public release, especially for optional integrations, external feeds and
redistribution of third-party data.
