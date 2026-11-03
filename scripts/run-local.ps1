<#
.SYNOPSIS
    Starts the Netrigil desktop shell.

.DESCRIPTION
    Without parameters: runs the latest source with `dotnet run` (requires the .NET SDK).
    -Standalone: starts the published single-file EXE (no SDK needed); publishes it first if missing.

.EXAMPLE
    .\scripts\run-local.ps1

.EXAMPLE
    .\scripts\run-local.ps1 -Standalone
#>
param(
    [switch]$Standalone
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "artifacts\publish\win-x64\Netrigil.Desktop.exe"

if ($Standalone) {
    if (-not (Test-Path $exe)) {
        & (Join-Path $PSScriptRoot "publish-standalone.ps1")
    }

    Start-Process -FilePath $exe
    Write-Host "Started: $exe" -ForegroundColor Green
    return
}

$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if ($dotnet) {
    $sdks = & $dotnet --list-sdks 2>$null
    if (-not $sdks) { $dotnet = $null }
}

if (-not $dotnet) {
    $perUser = Join-Path $env:USERPROFILE ".dotnet\dotnet.exe"
    if (Test-Path $perUser) { $dotnet = $perUser }
}

if (-not $dotnet) { throw "dotnet CLI not found on PATH. Install the .NET 10 SDK (global.json) or use -Standalone." }

& $dotnet run --project (Join-Path $root "src\Netrigil.Desktop\Netrigil.Desktop.csproj") -c Release
