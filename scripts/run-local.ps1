<#
.SYNOPSIS
    Pokreće LocalFirewall demo shell.

.DESCRIPTION
    Bez parametara: pokreće najnoviji kod preko `dotnet run` (potreban .NET SDK).
    -Standalone:   pokreće već publikovan single-file EXE (bez SDK-a); ako ne postoji, prvo ga publikuje.

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
$exe = Join-Path $root "artifacts\publish\win-x64\LocalFirewall.Desktop.exe"

if ($Standalone) {
    if (-not (Test-Path $exe)) {
        & (Join-Path $PSScriptRoot "publish-standalone.ps1")
    }

    Start-Process -FilePath $exe
    Write-Host "Pokrenuto: $exe" -ForegroundColor Green
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

if (-not $dotnet) { throw "dotnet CLI nije na PATH. Instaliraj .NET 10 SDK (global.json) ili koristi -Standalone." }

& $dotnet run --project (Join-Path $root "src\LocalFirewall.Desktop\LocalFirewall.Desktop.csproj") -c Release
