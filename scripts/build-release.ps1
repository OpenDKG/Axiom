# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Builds the portable Netpetra release archive and checksum file.

.DESCRIPTION
    Publishes the standalone Windows x64 build, packs Netpetra.Desktop.exe with the license and
    notice files, and writes SHA256SUMS.txt. No network upload, signing or installer is performed.

.PARAMETER Version
    Release version. Defaults to the Version property in Directory.Build.props.

.PARAMETER OutputDir
    Release output directory. Defaults to artifacts\release.

.EXAMPLE
    .\scripts\build-release.ps1

.EXAMPLE
    .\scripts\build-release.ps1 -Version 0.2.1
#>
param(
    [string]$Version = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

function Resolve-Dotnet {
    $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    if ($dotnet) {
        $sdks = & $dotnet --list-sdks 2>$null
        if (-not $sdks) { $dotnet = $null }
    }

    if (-not $dotnet) {
        $perUser = Join-Path $env:USERPROFILE ".dotnet\dotnet.exe"
        if (Test-Path $perUser) { $dotnet = $perUser }
    }

    if (-not $dotnet) { throw "dotnet CLI not found. Install the .NET 10 SDK." }
    return $dotnet
}

if (-not $Version) {
    $props = Get-Content (Join-Path $root "Directory.Build.props") -Raw
    $match = [regex]::Match($props, "<Version>([^<]+)</Version>")
    if (-not $match.Success) { throw "Could not read Version from Directory.Build.props." }
    $Version = $match.Groups[1].Value.Trim()
}

if (-not $OutputDir) {
    $OutputDir = Join-Path $root "artifacts\release"
}

$dotnet = Resolve-Dotnet
$project = Join-Path $root "src\Netpetra.Desktop\Netpetra.Desktop.csproj"

Write-Host "Publishing Netpetra $Version (win-x64)..." -ForegroundColor Cyan
& $dotnet publish $project -c Release -p:PublishProfile=win-x64-selfcontained
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

$exe = Join-Path $root "artifacts\publish\win-x64\Netpetra.Desktop.exe"
if (-not (Test-Path $exe)) { throw "Published executable not found: $exe" }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$zipName = "Netpetra-$Version-win-x64.zip"
$zipPath = Join-Path $OutputDir $zipName

$files = @(
    $exe,
    (Join-Path $root "LICENSE"),
    (Join-Path $root "NOTICE"),
    (Join-Path $root "THIRD_PARTY_NOTICES.md"),
    (Join-Path $root "scripts\install-portable.ps1"),
    (Join-Path $root "scripts\uninstall-portable.ps1")
) | Where-Object { Test-Path $_ }

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $files -DestinationPath $zipPath -Force

$hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
$checksumPath = Join-Path $OutputDir "SHA256SUMS.txt"
"$hash  $zipName" | Set-Content $checksumPath -Encoding ASCII

Write-Host "Release: $zipPath" -ForegroundColor Green
Write-Host "Checksum: $checksumPath"
Write-Host "  $hash  $zipName"
