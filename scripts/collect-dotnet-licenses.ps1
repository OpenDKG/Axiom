# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Writes the .NET license texts a Windows release must carry into <OutputDir>/dotnet.

.DESCRIPTION
    Reads the runtime version from each published single-file program, and copies Microsoft's .NET
    Library License text plus that runtime pack's LICENSE.TXT and THIRD-PARTY-NOTICES.TXT. Stops when
    a text is missing, or when the programs were built with different runtime versions. Must stay
    compatible with Windows PowerShell 5.1.
#>
param(
    [Parameter(Mandatory = $true)][string[]]$Program,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$PackagesRoot
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "lib/SingleFileBundle.ps1")
$root = Split-Path -Parent $PSScriptRoot
if (-not $PackagesRoot) {
    if ($env:NUGET_PACKAGES) { $PackagesRoot = $env:NUGET_PACKAGES }
    else { $PackagesRoot = Join-Path ([System.Environment]::GetFolderPath("UserProfile")) ".nuget/packages" }
}

$versions = @(foreach ($path in $Program) {
        $bundle = Read-SingleFileBundle -Path $path
        if ($null -eq $bundle) { throw "Not a .NET single-file program: $path" }
        $depsEntry = @($bundle.Entries | Where-Object { $_.Type -eq 3 })
        if ($depsEntry.Count -ne 1) { throw "No deps.json inside $path" }
        $deps = [System.Text.Encoding]::UTF8.GetString((Get-BundleEntryBytes $bundle $depsEntry[0]))
        $found = [regex]::Matches($deps, '"runtimepack\.Microsoft\.NETCore\.App\.Runtime\.win-x64/([0-9][^"]*)"')
        if ($found.Count -eq 0) { throw "No .NET runtime pack named inside $path" }
        $found[0].Groups[1].Value
    }) | Select-Object -Unique
if (@($versions).Count -ne 1) { throw "The programs were built with different .NET runtimes: $($versions -join ', ')" }

$pack = Join-Path $PackagesRoot "microsoft.netcore.app.runtime.win-x64/$versions"
$sources = @(
    (Join-Path $root "packaging/licenses/dotnet/DOTNET-LIBRARY-LICENSE.txt"),
    (Join-Path $pack "LICENSE.TXT"),
    (Join-Path $pack "THIRD-PARTY-NOTICES.TXT")
)
foreach ($source in $sources) {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or (Get-Item -LiteralPath $source).Length -eq 0) {
        throw "License text is missing or empty: $source"
    }
}

$target = Join-Path $OutputDir "dotnet"
New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($source in $sources) { Copy-Item -LiteralPath $source -Destination $target -Force }
Write-Host "Collected the .NET $versions license texts into $target."
