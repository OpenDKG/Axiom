# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Removes the per-user portable Netrigil installation.

.DESCRIPTION
    Removes only the files installed by install-portable.ps1 (Netrigil.Desktop.exe, install.json)
    and the Start Menu shortcut. User data is kept unless -RemoveData is specified. No administrator
    rights are required and no Windows service or firewall rule is touched.

.PARAMETER InstallDir
    Installation directory. Defaults to %LOCALAPPDATA%\Programs\Netrigil.

.PARAMETER RemoveData
    Also remove the local Netrigil database (netrigil.db and WAL sidecars). Unknown files are kept.

.EXAMPLE
    .\scripts\uninstall-portable.ps1

.EXAMPLE
    .\scripts\uninstall-portable.ps1 -RemoveData
#>
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Netrigil"),
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

if (Get-Process -Name "Netrigil.Desktop" -ErrorAction SilentlyContinue) {
    throw "Netrigil is running. Close it before uninstalling."
}

$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $startMenu "Netrigil.lnk"
if (Test-Path $shortcutPath) {
    Remove-Item $shortcutPath -Force
    Write-Host "Removed shortcut: $shortcutPath"
}

$installedFiles = @(
    (Join-Path $InstallDir "Netrigil.Desktop.exe"),
    (Join-Path $InstallDir "install.json")
)

foreach ($file in $installedFiles) {
    if (Test-Path $file) {
        Remove-Item $file -Force
        Write-Host "Removed: $file"
    }
}

if (Test-Path $InstallDir) {
    $remaining = @(Get-ChildItem $InstallDir -Force)
    if ($remaining.Count -eq 0) {
        Remove-Item $InstallDir -Force
        Write-Host "Removed empty directory: $InstallDir"
    }
    else {
        Write-Host "Kept $InstallDir because it still contains files:" -ForegroundColor Yellow
        $remaining | ForEach-Object { Write-Host "  $($_.Name)" }
    }
}

if ($RemoveData) {
    $dataDir = Join-Path $env:LOCALAPPDATA "Netrigil"
    foreach ($name in @("netrigil.db", "netrigil.db-wal", "netrigil.db-shm")) {
        $path = Join-Path $dataDir $name
        if (Test-Path $path) {
            Remove-Item $path -Force
            Write-Host "Removed data file: $path"
        }
    }

    if (Test-Path $dataDir) {
        $remainingData = @(Get-ChildItem $dataDir -Force)
        if ($remainingData.Count -eq 0) {
            Remove-Item $dataDir -Force
            Write-Host "Removed empty data directory: $dataDir"
        }
    }
}
else {
    Write-Host "Local data was kept at $(Join-Path $env:LOCALAPPDATA 'Netrigil'). Use -RemoveData to delete it."
}

Write-Host "Netrigil portable installation removed." -ForegroundColor Green
