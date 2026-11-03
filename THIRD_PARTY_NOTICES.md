# Third-party notices

This file lists the NuGet packages in the locked dependency graph (packages.lock.json) of
Netpetra, generated on 2026-11-03. Licenses were read from each package's
.nuspec on NuGet.org at that date.

The project itself is licensed under **GPL-3.0-or-later** (see LICENSE and NOTICE). All listed
packages are permissive (MIT or Apache-2.0) and are compatible with that license. No GPL/AGPL
third-party code is included.

The self-contained standalone build also redistributes the .NET 10 runtime and Windows Desktop
runtime, which are MIT licensed (https://github.com/dotnet/runtime/blob/main/LICENSE.TXT).

## Runtime packages shipped with the application

| Package | Version | License |
|---|---|---|
| CommunityToolkit.Mvvm | 8.4.2 | MIT |
| Microsoft.Data.Sqlite | 10.0.14 | MIT |
| Microsoft.Data.Sqlite.Core | 10.0.14 | MIT |
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

## Notes

- SQLite itself is in the public domain; the SQLitePCLRaw.* packages that bundle it are
  Apache-2.0.
- Package versions are pinned in Directory.Packages.props and packages.lock.json; update this
  file whenever the locked graph changes.
- Optional integration modules (integrations/) may carry their own licenses (for example
  MIT/Apache-2.0) and must keep their notices separate from the GPL-3.0-or-later desktop/service.