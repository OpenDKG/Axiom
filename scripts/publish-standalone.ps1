<#
.SYNOPSIS
    Publishes the standalone (self-contained) Windows x64 shell.

.DESCRIPTION
    Produces a single Netrigil.UI.exe that runs without a .NET runtime installed.
    WPF does not support trimming, so PublishTrimmed stays false. The output lands in
    artifacts\publish\win-x64 by default.

.PARAMETER Output
    Optional output directory; defaults to the publish profile value.

.EXAMPLE
    .\scripts\publish-standalone.ps1

.EXAMPLE
    .\scripts\publish-standalone.ps1 -Output D:\Dist\Netrigil
#>
param(
    [string]$Output
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root "src\Netrigil.Desktop\Netrigil.Desktop.csproj"

$arguments = @(
    "publish", $project,
    "-c", "Release",
    "-p:PublishProfile=win-x64-selfcontained"
)

if ($Output) {
    $arguments += @("-o", $Output)
}

Write-Host "Publishing standalone win-x64 build..." -ForegroundColor Cyan
$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if ($dotnet) {
    $sdks = & $dotnet --list-sdks 2>$null
    if (-not $sdks) { $dotnet = $null }
}

if (-not $dotnet) {
    $perUser = Join-Path $env:USERPROFILE ".dotnet\dotnet.exe"
    if (Test-Path $perUser) { $dotnet = $perUser }
}

if (-not $dotnet) { throw "dotnet CLI not found. Install the .NET 10 SDK pinned in global.json." }

& $dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

if (-not $Output) {
    $Output = Join-Path $root "artifacts\publish\win-x64"
}

$exe = Join-Path $Output "Netrigil.Desktop.exe"
if (-not (Test-Path $exe)) { throw "Expected executable not found: $exe" }

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Done: $exe ($size MB, self-contained single file)" -ForegroundColor Green
