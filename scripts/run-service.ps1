<#
.SYNOPSIS
    Pokreće servis u konzolnom (development) režimu i UI preko Named Pipe-a.

.DESCRIPTION
    Ne instalira Windows servis i ne traži administratora. Servis se pokreće kao običan proces
    (allowed SID = trenutni korisnik), UI se pokreće sa --service i čita snapshot preko pipe-a.
    Kada se UI zatvori, servis se zaustavlja (osim uz -KeepServiceRunning).

.EXAMPLE
    .\scripts\run-service.ps1

.EXAMPLE
    .\scripts\run-service.ps1 -KeepServiceRunning
#>
param(
    [switch]$KeepServiceRunning
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

    if (-not $dotnet) { throw "dotnet CLI nije pronađen. Instaliraj .NET 10 SDK." }
    return $dotnet
}

$dotnet = Resolve-Dotnet
$serviceProject = Join-Path $root "src\LocalFirewall.Service\LocalFirewall.Service.csproj"
$desktopProject = Join-Path $root "src\LocalFirewall.Desktop\LocalFirewall.Desktop.csproj"
$serviceLog = Join-Path $env:TEMP "localfirewall-service.log"
$serviceError = Join-Path $env:TEMP "localfirewall-service.err.log"

Write-Host "Pokrećem servis (konzolni režim)..." -ForegroundColor Cyan
$service = Start-Process -FilePath $dotnet `
    -ArgumentList @("run", "--project", $serviceProject, "-c", "Release", "--no-build") `
    -PassThru -RedirectStandardOutput $serviceLog -RedirectStandardError $serviceError

try {
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-Path "\\.\pipe\LocalFirewall.Service.v1") { $ready = $true; break }
        if ($service.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }

    if (-not $ready) {
        Write-Host "Servis nije podigao pipe. Log:" -ForegroundColor Red
        Get-Content $serviceLog -ErrorAction SilentlyContinue | Select-Object -Last 20
        Get-Content $serviceError -ErrorAction SilentlyContinue | Select-Object -Last 20
        throw "Servis nije spreman."
    }

    Write-Host "Servis radi. Pokrećem UI sa --service..." -ForegroundColor Cyan
    & $dotnet run --project $desktopProject -c Release --no-build -- --service
}
finally {
    if (-not $KeepServiceRunning -and -not $service.HasExited) {
        Write-Host "Zaustavljam servis..." -ForegroundColor Cyan
        $service | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
