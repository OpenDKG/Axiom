# Third-party notices

This file lists the NuGet packages in the locked dependency graph (packages.lock.json) of
Axiom, generated on 2026-11-04. Licenses were read from each package's
.nuspec on NuGet.org at that date.

The project itself is licensed under **GPL-3.0-or-later** (see LICENSE and NOTICE). All listed
packages are permissive (MIT or Apache-2.0) and are compatible with that license. No GPL/AGPL
third-party code is included. The .NET runtime in Windows releases is covered separately below.

## .NET runtime and native binaries in Windows releases

The Windows programs (`Axiom.Desktop.exe`, `Axiom.Service.exe` and Setup) are self-contained,
single-file builds that redistribute the .NET 10 runtime. No Windows Desktop (WPF) runtime is
included.

| Component | License | Text in the release |
|---|---|---|
| .NET single-file host: the launcher of each program, with the runtime and `coreclr` built in (`Microsoft.NETCore.App.Host.win-x64`) | **.NET Library License** (proprietary, Microsoft) | `licenses/dotnet/DOTNET-LIBRARY-LICENSE.txt` |
| Other .NET runtime files packed inside the programs (`Microsoft.NETCore.App.Runtime.win-x64`) | MIT, per Microsoft's [Windows license information](https://github.com/dotnet/core/blob/main/license-information-windows.md), with third-party notices | `licenses/dotnet/LICENSE.TXT`, `licenses/dotnet/THIRD-PARTY-NOTICES.TXT` |

**Whether GPL-3.0-or-later programs may be distributed with the .NET Library License component needs
review by the founders or a lawyer.** It is not settled; see [docs/LICENSING.md](docs/LICENSING.md).
`Microsoft.DiaSymReader.Native`, also under that license, is not shipped.

Native libraries packed inside the programs, besides the host:

| File | NuGet package | License |
|---|---|---|
| `av_libglesv2.dll` | Avalonia.Angle.Windows.Natives (ANGLE) | BSD-3-Clause |
| `libHarfBuzzSharp.dll` | HarfBuzzSharp.NativeAssets.Win32 | MIT, with third-party notices |
| `libSkiaSharp.dll` | SkiaSharp.NativeAssets.Win32 | MIT, with third-party notices |
| `e_sqlite3.dll` | SQLitePCLRaw.lib.e_sqlite3 | Apache-2.0 package; SQLite itself is public domain |

The license texts of these four libraries are not yet part of the release.

## Runtime packages shipped with the application

| Package | Version | License |
|---|---|---|
| CommunityToolkit.Mvvm | 8.4.2 | MIT |
| Microsoft.Data.Sqlite | 10.0.14 | MIT |
| Microsoft.Data.Sqlite.Core | 10.0.14 | MIT |
| Microsoft.Extensions.AI.Abstractions | 10.11.0 | MIT |
| Microsoft.Extensions.Caching.Abstractions | 10.0.13 | MIT |
| Microsoft.Extensions.Configuration | 10.0.14 | MIT |
| Microsoft.Extensions.Configuration.Abstractions | 10.0.14 | MIT |
| Microsoft.Extensions.Configuration.Binder | 10.0.14 | MIT |
| Microsoft.Extensions.Configuration.CommandLine | 10.0.14 | MIT |
| Microsoft.Extensions.Configuration.EnvironmentVariables | 10.0.14 | MIT |
| Microsoft.Extensions.Configuration.FileExtensions | 10.0.14 | MIT |
| Microsoft.Extensions.Configuration.Json | 10.0.14 | MIT |
| Microsoft.Extensions.Configuration.UserSecrets | 10.0.14 | MIT |
| Microsoft.Extensions.DependencyInjection | 10.0.14 | MIT |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.14 | MIT |
| Microsoft.Extensions.Diagnostics | 10.0.14 | MIT |
| Microsoft.Extensions.Diagnostics.Abstractions | 10.0.14 | MIT |
| Microsoft.Extensions.FileProviders.Abstractions | 10.0.14 | MIT |
| Microsoft.Extensions.FileProviders.Physical | 10.0.14 | MIT |
| Microsoft.Extensions.FileSystemGlobbing | 10.0.14 | MIT |
| Microsoft.Extensions.Hosting | 10.0.14 | MIT |
| Microsoft.Extensions.Hosting.Abstractions | 10.0.14 | MIT |
| Microsoft.Extensions.Hosting.WindowsServices | 10.0.14 | MIT |
| Microsoft.Extensions.Logging | 10.0.14 | MIT |
| Microsoft.Extensions.Logging.Abstractions | 10.0.14 | MIT |
| Microsoft.Extensions.Logging.Configuration | 10.0.14 | MIT |
| Microsoft.Extensions.Logging.Console | 10.0.14 | MIT |
| Microsoft.Extensions.Logging.Debug | 10.0.14 | MIT |
| Microsoft.Extensions.Logging.EventLog | 10.0.14 | MIT |
| Microsoft.Extensions.Logging.EventSource | 10.0.14 | MIT |
| Microsoft.Extensions.Options | 10.0.14 | MIT |
| Microsoft.Extensions.Options.ConfigurationExtensions | 10.0.14 | MIT |
| Microsoft.Extensions.Primitives | 10.0.14 | MIT |
| ModelContextProtocol | 2.3.1 | Apache-2.0 |
| ModelContextProtocol.Core | 2.3.1 | Apache-2.0 |
| SQLitePCLRaw.bundle_e_sqlite3 | 2.1.13 | Apache-2.0 |
| SQLitePCLRaw.core | 2.1.13 | Apache-2.0 |
| SQLitePCLRaw.lib.e_sqlite3 | 2.1.13 | Apache-2.0 |
| SQLitePCLRaw.provider.e_sqlite3 | 2.1.13 | Apache-2.0 |
| System.Diagnostics.EventLog | 10.0.14 | MIT |
| System.ServiceProcess.ServiceController | 10.0.14 | MIT |

## Build and publish tooling

| Package | Version | License |
|---|---|---|
| Microsoft.NET.ILLink.Tasks | 10.0.14 | MIT |

## Test-only packages (not shipped)

| Package | Version | License |
|---|---|---|
| Microsoft.CodeCoverage | 17.14.1 | MIT |
| Microsoft.NET.Test.Sdk | 17.14.1 | MIT |
| Microsoft.TestPlatform.ObjectModel | 17.14.1 | MIT |
| Microsoft.TestPlatform.TestHost | 17.14.1 | MIT |
| Newtonsoft.Json | 13.0.3 | MIT |
| xunit | 2.9.3 | Apache-2.0 |
| xunit.abstractions | 2.0.3 | Apache-2.0 |
| xunit.analyzers | 1.18.0 | Apache-2.0 |
| xunit.assert | 2.9.3 | Apache-2.0 |
| xunit.core | 2.9.3 | Apache-2.0 |
| xunit.extensibility.core | 2.9.3 | Apache-2.0 |
| xunit.extensibility.execution | 2.9.3 | Apache-2.0 |
| xunit.runner.visualstudio | 2.8.2 | Apache-2.0 |

## Privacy Shield blocklist sources (downloaded at runtime, not bundled)

Privacy Shield does not ship these list bytes. It downloads them only when the user selects a
source and presses **Update sources now**. The source URL, license label and no-endorsement notice
are shown in the app. Re-check the upstream license before adding or redistributing a list.

| Source | License | Upstream |
|---|---|---|
| HaGeZi Multi PRO | GPL-3.0 | https://github.com/hagezi/dns-blocklists |
| OISD Big | GPL-3.0 | https://github.com/sjhgvr/oisd |
| WindowsSpyBlocker telemetry | MIT | https://github.com/crazy-max/WindowsSpyBlocker |
| The Block List Project - Ads | Unlicense | https://github.com/blocklistproject/Lists |
| The Block List Project - Tracking | Unlicense | https://github.com/blocklistproject/Lists |
| URLhaus malicious domains | CC0-1.0 / MIT | https://gitlab.com/malware-filter/urlhaus-filter. The label is the compiled list's. For the URLhaus data, the [abuse.ch terms of use](https://abuse.ch/terms-of-use/) say commercial use may need a paid Spamhaus subscription (section 4.1) and bar AI training on the data without Spamhaus' prior written consent. Their CC0 statement (section 3.4) covers Feodo Tracker, SSL Blacklist and YARAify, not URLhaus. |
| HaGeZi Threat Intelligence Feeds (Mini) | GPL-3.0 | https://github.com/hagezi/dns-blocklists |
| Phishing domains (OpenPhish / PhishTank) | CC-BY-SA-4.0 | https://gitlab.com/malware-filter/phishing-filter |

Each label is the license the list's publisher states, checked on 2026-11-26. The file header of The
Block List Project tracking list says MIT, while that repository's license is the Unlicense.

The two lists compiled by malware-filter are built from other feeds, which set their own terms:
[abuse.ch URLhaus](https://abuse.ch/terms-of-use/), [OpenPhish](https://openphish.com/terms.html),
[PhishTank](https://phishtank.org/faq.php#isitoktousetheapifor) and [IPThreat](https://ipthreat.net).

No provider endorses Axiom. A listing is a filtering decision, not a malware finding or a legal
claim. GPL-3.0, MIT and CC-BY-SA-4.0 sources have their own attribution/notice terms; Unlicense and
CC0 are public-domain dedications. Axiom is GPL-3.0-or-later and only references the upstream URLs.

## Notes

- SQLite itself is in the public domain; the SQLitePCLRaw.* packages that bundle it are
  Apache-2.0.
- Package versions are pinned in Directory.Packages.props and packages.lock.json; update this
  file whenever the locked graph changes.
- Optional integration modules (integrations/) may carry their own licenses (for example
  MIT/Apache-2.0) and must keep their notices separate from the GPL-3.0-or-later desktop/service.