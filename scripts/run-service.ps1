<#
.SYNOPSIS
    Starts the service in console (development) mode and the UI over the Named Pipe.

.DESCRIPTION
    Does not install a Windows service and does not require administrator rights. The service runs
    as a normal process (allowed SID = current user), the UI starts with --service and reads
    snapshots over the pipe. When the UI closes, the service is stopped unless -KeepServiceRunning
    is used.

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

    if (-not $dotnet) { throw "dotnet CLI not found. Install the .NET 10 SDK." }
    return $dotnet
}

$dotnet = Resolve-Dotnet
$serviceProject = Join-Path $root "src\Axiom.Service\Axiom.Service.csproj"
$desktopProject = Join-Path $root "src\Axiom.Desktop\Axiom.Desktop.csproj"
$serviceLog = Join-Path $env:TEMP "axiom-service.log"
$serviceError = Join-Path $env:TEMP "axiom-service.err.log"

Write-Host "Starting the service (console mode)..." -ForegroundColor Cyan
$service = Start-Process -FilePath $dotnet `
    -ArgumentList @("run", "--project", $serviceProject, "-f", "net10.0-windows", "-c", "Release", "--no-build") `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput $serviceLog -RedirectStandardError $serviceError

try {
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-Path "\\.\pipe\Axiom.Service.v1") { $ready = $true; break }
        if ($service.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }

    if (-not $ready) {
        Write-Host "The service did not create the pipe. Log:" -ForegroundColor Red
        Get-Content $serviceLog -ErrorAction SilentlyContinue | Select-Object -Last 20
        Get-Content $serviceError -ErrorAction SilentlyContinue | Select-Object -Last 20
        throw "The service is not ready."
    }

    Write-Host "Service is running. Starting the UI with --service..." -ForegroundColor Cyan
    & $dotnet run --project $desktopProject -c Release --no-build -- --service
}
finally {
    if (-not $KeepServiceRunning -and -not $service.HasExited) {
        Write-Host "Stopping the service..." -ForegroundColor Cyan
        $service | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
