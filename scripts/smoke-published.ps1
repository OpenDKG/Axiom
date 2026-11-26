# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Starts the published Windows desktop app and service and checks that both keep running.

.DESCRIPTION
    For a disposable CI machine: it really starts both programs. Each must still run after the wait
    and must have loaded a native library that is packed inside its single file. The service gets a
    temporary data folder.
#>
param(
    [Parameter(Mandatory = $true)][string]$Desktop,
    [Parameter(Mandatory = $true)][string]$Service,
    [int]$Seconds = 25
)

$ErrorActionPreference = "Stop"
$logs = Join-Path ([System.IO.Path]::GetTempPath()) ("axiom-smoke-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$crashLog = Join-Path $env:LOCALAPPDATA "Axiom\logs\crash.log"
Remove-Item -LiteralPath $crashLog -Force -ErrorAction SilentlyContinue
$env:AXIOM_DATA_DIR = Join-Path $logs "data"

function Test-StaysUp([string]$Name, [string]$Path, [string]$Library) {
    $out = Join-Path $logs "$Name.out.txt"
    $err = Join-Path $logs "$Name.err.txt"
    $process = Start-Process -FilePath (Resolve-Path -LiteralPath $Path).Path -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    try {
        Start-Sleep -Seconds $Seconds
        $process.Refresh()
        $output = (Get-Content -LiteralPath $out, $err -ErrorAction SilentlyContinue | Select-Object -Last 40) -join "`n"
        if (Test-Path -LiteralPath $crashLog) { $output += "`n" + (Get-Content -LiteralPath $crashLog -Raw) }
        if ($process.HasExited) { throw "$Name exited with code $($process.ExitCode).`n$output" }
        $modules = @((Get-Process -Id $process.Id).Modules | ForEach-Object { $_.ModuleName })
        if ($modules -notcontains $Library) { throw "$Name runs but did not load $Library.`n$output`nLoaded: $($modules -join ', ')" }
        Write-Host "$Name started, loaded $Library and was still running after $Seconds seconds."
    }
    finally {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit(10000) | Out-Null }
    }
}

Test-StaysUp "Axiom desktop" $Desktop "libSkiaSharp.dll"
Test-StaysUp "Axiom service" $Service "e_sqlite3.dll"
if (Test-Path -LiteralPath $crashLog) { throw "The desktop wrote a crash log:`n$(Get-Content -LiteralPath $crashLog -Raw)" }
