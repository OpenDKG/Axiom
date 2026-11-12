# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Publishes the single-file Axiom Setup executable with an embedded desktop/service payload.

.DESCRIPTION
    First publishes the self-contained desktop and service, then embeds them into Axiom.Setup.exe (internal executable name).
    The resulting setup EXE needs no .NET runtime and installs the application per user.
#>
param(
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
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

if (-not $OutputDir) {
    $OutputDir = Join-Path $root "artifacts\publish\setup"
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputDir)
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $root "artifacts"))
if (-not ($resolvedOutput -eq $artifactsRoot -or
          $resolvedOutput.StartsWith($artifactsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) {
    throw "OutputDir must stay inside $artifactsRoot."
}
$OutputDir = $resolvedOutput

$desktopOut = Join-Path $root "artifacts\publish\win-x64"
$serviceOut = Join-Path $root "artifacts\publish\service"
$payloadOut = Join-Path $root "artifacts\publish\setup-payload"
$setupProject = Join-Path $root "src\Axiom.Setup\Axiom.Setup.csproj"

Write-Host "Publishing desktop payload..." -ForegroundColor Cyan
& $dotnet publish (Join-Path $root "src\Axiom.Desktop.Avalonia.Windows\Axiom.Desktop.Avalonia.Windows.csproj") `
    -c Release -p:PublishProfile=win-x64-selfcontained
if ($LASTEXITCODE -ne 0) { throw "Desktop publish failed." }

Write-Host "Publishing service payload..." -ForegroundColor Cyan
Remove-Item $serviceOut -Recurse -Force -ErrorAction SilentlyContinue
& $dotnet publish (Join-Path $root "src\Axiom.Service\Axiom.Service.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None -o $serviceOut
if ($LASTEXITCODE -ne 0) { throw "Service publish failed." }

Remove-Item $payloadOut -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $payloadOut | Out-Null
Copy-Item (Join-Path $desktopOut "Axiom.Desktop.exe") $payloadOut -Force
Copy-Item (Join-Path $serviceOut "Axiom.Service.exe") $payloadOut -Force
Copy-Item (Join-Path $desktopOut "community") $payloadOut -Recurse -Force

Remove-Item $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Publishing setup EXE..." -ForegroundColor Cyan
& $dotnet publish $setupProject `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true -p:DebugType=None `
    -p:AxiomPayloadDir="$payloadOut" -o $OutputDir
if ($LASTEXITCODE -ne 0) { throw "Setup publish failed." }

$setupExe = Join-Path $OutputDir "Axiom.Setup.exe"
if (-not (Test-Path $setupExe)) { throw "Setup executable not found: $setupExe" }

$size = [math]::Round((Get-Item $setupExe).Length / 1MB, 1)
Write-Host "Done: $setupExe ($size MB, self-contained single-file setup)" -ForegroundColor Green
