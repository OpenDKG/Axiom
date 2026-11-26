# Licensing

## Decision

The desktop application, the Windows service and the core libraries are licensed under
**GNU General Public License v3.0 or later** (`GPL-3.0-or-later`).

- Full text: [`LICENSE`](../LICENSE)
- Copyright and grant: [`NOTICE`](../NOTICE)
- Authors, copyright holders, maintainers and contributors: [`AUTHORS.md`](../AUTHORS.md)
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

The pinned NuGet dependencies listed below are MIT or Apache-2.0, which are compatible with
GPL-3.0-or-later. This covers NuGet packages only. The .NET runtime in Windows releases is a separate
matter with an open question; see the next section.

- MIT: CommunityToolkit.Mvvm, Microsoft.Data.Sqlite, Microsoft.Extensions.*, Microsoft.NET.Test.Sdk,
  Microsoft.NET.ILLink.Tasks.
- Apache-2.0: SQLitePCLRaw.*, xunit.*.

The exact versions and licenses are generated from `packages.lock.json` into
`THIRD_PARTY_NOTICES.md`. Update that file whenever the locked graph changes.

Apache-2.0 code is compatible with GPLv3 (patent and notice terms), but **not** with GPLv2. Do not
downgrade the project license to GPLv2 without a full dependency review.

## .NET runtime in Windows releases

An earlier version of this document said the whole self-contained runtime is MIT. That was wrong for
the Windows releases.

Microsoft's [Windows license information](https://github.com/dotnet/core/blob/main/license-information-windows.md)
puts these under the proprietary
[.NET Library License](https://dotnet.microsoft.com/dotnet_library_license.htm), and all other files of
the Windows distribution under MIT (except one WPF file under the Windows SDK License):

- "coreclr.dll and .NET runtimes included in binaries published as single-file";
- `Microsoft.DiaSymReader.Native.*.dll`;
- four WPF files. No Windows release program contains WPF.

Microsoft's general [license information](https://github.com/dotnet/core/blob/main/license-information.md)
page also says that Windows product distributions, runtime packs included, use the .NET Library
License. This document follows the file-by-file Windows page. A legal review must confirm that. It
should also confirm the first item above: the sentence can be read as covering `coreclr.dll` only in
single-file builds, or in every build.

**Single-file programs.** The desktop app, the service and Setup are single-file. Each starts with
.NET's single-file host, which has the runtime, `coreclr` included, built in. So all three Windows
programs contain code under the .NET Library License. Releases ship its text as
`licenses/dotnet/DOTNET-LIBRARY-LICENSE.txt`, next to the runtime's MIT `LICENSE.TXT` and
`THIRD-PARTY-NOTICES.TXT`. The portable ZIP and the Store package carry that folder, and Setup and
`install-portable.ps1` put it in the install folder.

**Open, and not decided here: whether Axiom may distribute GPL-3.0-or-later programs that include a
runtime under the .NET Library License needs review by the founders or a lawyer. Shipping the license
text does not answer it, and this document does not claim it is acceptable.** The review should read
the whole license. Among its terms for distributed code (section 3): distributors and external end
users must agree to terms that protect it at least as much as that agreement; the distributor must
defend and indemnify Microsoft against claims related to the distribution or use of the application;
and it restricts distributing that code so that it becomes subject to a license that requires source
disclosure or modification rights. Axiom has not added any terms for end users.

**DiaSymReader is not shipped.** The SDK already leaves it out of single-file publishes, and
`Directory.Build.targets` removes it from every other publish and from `deps.json`. The runtime uses
it only to read Windows-format PDBs. The released 1.5.2 desktop app, service, Setup, Linux package
and macOS package do not contain it. The 1.5.2 releases also do not carry the .NET license texts.

**Linux and macOS** releases are published as multiple files, and Microsoft licenses .NET on those
systems under MIT.

**Checks.** The Windows release scripts run `scripts/verify-publish-natives.ps1`. It fails on a native
binary that is not recorded in `packaging/licenses/native-binaries.json` and named in
`THIRD_PARTY_NOTICES.md`, and on the restricted files above, apart from the runtime built into the
single-file host. Changing how a program is published changes its native files, so the check then
fails until their licenses are reviewed and recorded.

## Optional integration modules

Modules under `integrations/` (for example the future agent-security-memory package) are separate
works and may use **MIT or Apache-2.0** so they can be consumed by other ecosystems and registries.
Rules:

- No GPL-3.0-only code may be copied into an MIT/Apache-2.0 module.
- Each module keeps its own `LICENSE`, `NOTICE` and third-party notices.
- The GPL desktop/service may reference a permissively licensed module, but the module must not
  depend on GPL-only code.
- Shared protocol/schema definitions should live in `Axiom.Contracts` under GPL-3.0-or-later
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
- keep `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` and the `licenses/` folder,
- state any modifications,
- do not imply official status for unofficial builds (see `TRADEMARKS.md`).

## Legal review

This document records an engineering decision, not legal advice. A legal/license review is required
before the first public release, especially for optional integrations, external feeds and
redistribution of third-party data.
