# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Measures CPU and working-set usage of the Netrigil service and UI.

.DESCRIPTION
    Starts the built service in console mode and the published UI with --service, warms up, samples
    both processes for the requested duration, writes a CSV and prints a summary. The script stops
    only the processes it started. No administrator rights, firewall change or network access.

.PARAMETER Seconds
    Sampling duration after warm-up. Default 60.

.PARAMETER IntervalSeconds
    Sampling interval. Default 2.

.EXAMPLE
    .\scripts\measure-performance.ps1

.EXAMPLE
    .\scripts\measure-performance.ps1 -Seconds 30
#>
param(
    [int]$Seconds = 60,
    [int]$IntervalSeconds = 2
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$serviceExe = Join-Path $root "src\Netrigil.Service\bin\Release\net10.0-windows\Netrigil.Service.exe"
$uiExe = Join-Path $root "artifacts\publish\win-x64\Netrigil.Desktop.exe"

if (-not (Test-Path $serviceExe)) { throw "Service build not found: $serviceExe. Run dotnet build first." }
if (-not (Test-Path $uiExe)) { throw "Published UI not found: $uiExe. Run .\scripts\publish-standalone.ps1 first." }
if (Get-Process -Name "Netrigil.Desktop","Netrigil.Service" -ErrorAction SilentlyContinue) {
    throw "Netrigil is already running. Close it before measuring."
}

$outputDir = Join-Path $root "artifacts\performance"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = Join-Path $outputDir "netrigil-$stamp.csv"
$logPath = Join-Path $env:TEMP "netrigil-performance-service.log"

$service = $null
$ui = $null

try {
    Write-Host "Starting service..." -ForegroundColor Cyan
    $service = Start-Process -FilePath $serviceExe -PassThru -RedirectStandardOutput $logPath -RedirectStandardError "$logPath.err"

    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-Path "\\.\pipe\Netrigil.Service.v1") { $ready = $true; break }
        if ($service.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) { throw "Service did not create the pipe. See $logPath." }

    Write-Host "Starting UI..." -ForegroundColor Cyan
    $ui = Start-Process -FilePath $uiExe -ArgumentList "--service" -PassThru
    Start-Sleep -Seconds 10

    $service.Refresh()
    $ui.Refresh()
    $lastServiceCpu = $service.TotalProcessorTime
    $lastUiCpu = $ui.TotalProcessorTime
    $last = Get-Date

    $rows = [System.Collections.Generic.List[object]]::new()

    Write-Host "Sampling for $Seconds s every $IntervalSeconds s..." -ForegroundColor Cyan
    for ($elapsed = 0; $elapsed -lt $Seconds; $elapsed += $IntervalSeconds) {
        Start-Sleep -Seconds $IntervalSeconds
        $now = Get-Date
        $seconds = ($now - $last).TotalSeconds
        $last = $now

        foreach ($pair in @(@("service", $service, $lastServiceCpu), @("ui", $ui, $lastUiCpu))) {
            $name = $pair[0]
            $process = $pair[1]
            $process.Refresh()
            if ($process.HasExited) { continue }
            $cpuTime = $process.TotalProcessorTime
            $previous = $pair[2]
            $cpuPercent = (($cpuTime - $previous).TotalMilliseconds / ($seconds * 1000)) / [Environment]::ProcessorCount * 100
            $rows.Add([pscustomobject]@{
                TimestampUtc = $now.ToUniversalTime().ToString("O")
                Process      = $name
                CpuPercent   = [math]::Round($cpuPercent, 2)
                WorkingSetMB = [math]::Round($process.WorkingSet64 / 1MB, 1)
            })
        }

        $lastServiceCpu = $service.TotalProcessorTime
        $lastUiCpu = $ui.TotalProcessorTime
    }

    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nSummary" -ForegroundColor Green
    $rows | Group-Object Process | ForEach-Object {
        $avgCpu = ($_.Group | Measure-Object CpuPercent -Average).Average
        $peakWs = ($_.Group | Measure-Object WorkingSetMB -Maximum).Maximum
        "{0,-8} average CPU {1,6:N2}%  peak working set {2,7:N1} MB" -f $_.Name, $avgCpu, $peakWs
    }
    Write-Host "CSV: $csvPath"
}
finally {
    if ($ui -and -not $ui.HasExited) { $ui | Stop-Process -Force -ErrorAction SilentlyContinue }
    if ($service -and -not $service.HasExited) { $service | Stop-Process -Force -ErrorAction SilentlyContinue }
}
