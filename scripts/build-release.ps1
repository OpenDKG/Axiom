# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Builds the portable Axiom release archive and checksum file.

.DESCRIPTION
    Publishes the standalone Windows x64 desktop and service builds, packs both executables with the
    license and notice files, and writes SHA256SUMS.txt. No network upload, signing or installer is
    performed.

.PARAMETER Version
    Release version. Defaults to the Version property in Directory.Build.props.

.PARAMETER OutputDir
    Release output directory. Defaults to artifacts\release.

.EXAMPLE
    .\scripts\build-release.ps1

.EXAMPLE
    .\scripts\build-release.ps1 -Version 0.4.21
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
        foreach ($candidate in @(
            (Join-Path $env:USERPROFILE ".dotnet-sdk\dotnet.exe"),
            (Join-Path $env:USERPROFILE ".dotnet\dotnet.exe")
        )) {
            if (Test-Path $candidate) { $dotnet = $candidate; break }
        }
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
$serviceProject = Join-Path $root "src\Netpetra.Service\Netpetra.Service.csproj"

Write-Host "Publishing Axiom $Version (win-x64)..." -ForegroundColor Cyan
& $dotnet publish $project -c Release -p:PublishProfile=win-x64-selfcontained
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

Write-Host "Publishing Axiom service $Version (win-x64, self-contained)..." -ForegroundColor Cyan
$serviceOutput = Join-Path $root "artifacts\publish\service"
Remove-Item $serviceOutput -Recurse -Force -ErrorAction SilentlyContinue
& $dotnet publish $serviceProject -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None `
    -o $serviceOutput
if ($LASTEXITCODE -ne 0) { throw "dotnet publish (service) failed with exit code $LASTEXITCODE." }

$exe = Join-Path $root "artifacts\publish\win-x64\Netpetra.Desktop.exe"
if (-not (Test-Path $exe)) { throw "Published executable not found: $exe" }

$serviceExe = Join-Path $serviceOutput "Netpetra.Service.exe"
if (-not (Test-Path $serviceExe)) { throw "Published service not found: $serviceExe" }

Write-Host "Publishing single-file Axiom Setup..." -ForegroundColor Cyan
$setupScript = Join-Path $PSScriptRoot "publish-setup.ps1"
$setupOutput = Join-Path $root "artifacts\publish\setup"
& powershell -NoProfile -ExecutionPolicy Bypass -File $setupScript -OutputDir $setupOutput
if ($LASTEXITCODE -ne 0) { throw "Setup publish failed with exit code $LASTEXITCODE." }

$setupExe = Join-Path $setupOutput "Netpetra.Setup.exe"
if (-not (Test-Path $setupExe)) { throw "Published setup not found: $setupExe" }

$communityDir = Join-Path $root "artifacts\publish\win-x64\community"
$communityFeed = Join-Path $communityDir "feed.json"
if (-not (Test-Path $communityFeed)) { throw "Bundled community feed not found: $communityFeed" }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$zipName = "Axiom-$Version-win-x64.zip"
$zipPath = Join-Path $OutputDir $zipName
$publicSetupExe = Join-Path $OutputDir "Axiom-Setup.exe"
Copy-Item $setupExe $publicSetupExe -Force

$files = @(
    $publicSetupExe,
    $exe,
    $serviceExe,
    $communityDir,
    (Join-Path $root "LICENSE"),
    (Join-Path $root "NOTICE"),
    (Join-Path $root "THIRD_PARTY_NOTICES.md"),
    (Join-Path $root "scripts\install-portable.ps1"),
    (Join-Path $root "scripts\uninstall-portable.ps1"),
    (Join-Path $root "scripts\install-from-github.ps1")
) | Where-Object { Test-Path $_ }

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $files -DestinationPath $zipPath -Force

$hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
$checksumPath = Join-Path $OutputDir "SHA256SUMS.txt"
"$hash  $zipName" | Set-Content $checksumPath -Encoding ASCII

Write-Host "Release: $zipPath" -ForegroundColor Green
Write-Host "Checksum: $checksumPath"
Write-Host "  $hash  $zipName"
