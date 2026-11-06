# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Removes the per-user portable Axiom installation.

.DESCRIPTION
    Removes only the files installed by install-portable.ps1 (Axiom.Desktop.exe,
    Axiom.Service.exe, install.json) and the Start Menu shortcut. User data is kept unless
    -RemoveData is specified. No administrator rights are required and no Windows service or firewall
    rule is touched.

.PARAMETER InstallDir
    Installation directory. Defaults to %LOCALAPPDATA%\Programs\Axiom.

.PARAMETER RemoveData
    Also remove the local Axiom database (axiom.db and WAL sidecars). Unknown files are kept.

.EXAMPLE
    .\scripts\uninstall-portable.ps1

.EXAMPLE
    .\scripts\uninstall-portable.ps1 -RemoveData
#>
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Axiom"),
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

function Test-ReparsePath {
    param([string]$Path)

    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
            if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                return $true
            }
        }

        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) {
            break
        }

        $current = $parent
    }

    return $false
}

function Remove-SafeItem {
    param(
        [string]$Path,
        [switch]$Recurse
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    if (Test-ReparsePath $Path) {
        Write-Warning "Skipped reparse point: $Path"
        return
    }

    if ($Recurse) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    else {
        Remove-Item -LiteralPath $Path -Force
    }
}

if (Get-Process -Name "Axiom.Desktop","Axiom.Service","Netpetra.Desktop","Netpetra.Service" -ErrorAction SilentlyContinue) {
    throw "Axiom is running. Close it before uninstalling."
}

$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
foreach ($startupName in @("Axiom", "Netpetra")) {
    $startupValue = Get-ItemProperty -Path $runKey -Name $startupName -ErrorAction SilentlyContinue
    if ($null -ne $startupValue) {
        Remove-ItemProperty -Path $runKey -Name $startupName -ErrorAction SilentlyContinue
        Write-Host "Removed $startupName autostart entry."
    }
}

$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $startMenu "Axiom.lnk"
$legacyShortcutPath = Join-Path $startMenu "Netpetra.lnk"
foreach ($candidate in @($shortcutPath, $legacyShortcutPath)) {
    if (Test-Path $candidate) {
        Remove-SafeItem -Path $candidate
        Write-Host "Removed shortcut: $candidate"
    }
}

$installedFiles = @(
    (Join-Path $InstallDir "Axiom.Desktop.exe"),
    (Join-Path $InstallDir "Axiom.Service.exe"),
    (Join-Path $InstallDir "Netpetra.Desktop.exe"),
    (Join-Path $InstallDir "Netpetra.Service.exe"),
    (Join-Path $InstallDir "install.json")
)

foreach ($file in $installedFiles) {
    if (Test-Path $file) {
        Remove-SafeItem -Path $file
        Write-Host "Removed: $file"
    }
}

$communityDir = Join-Path $InstallDir "community"
$communityFeed = Join-Path $communityDir "feed.json"
if (Test-Path $communityFeed) {
    Remove-SafeItem -Path $communityFeed
    Write-Host "Removed: $communityFeed"
}
if ((Test-Path $communityDir) -and -not (Get-ChildItem $communityDir -Force)) {
    Remove-SafeItem -Path $communityDir
}

$legacyInstallDir = Join-Path $env:LOCALAPPDATA "Programs\Netpetra"
foreach ($dir in @($InstallDir, $legacyInstallDir)) {
    if (Test-Path $dir) {
        $remaining = @(Get-ChildItem $dir -Force)
        if ($remaining.Count -eq 0) {
            Remove-SafeItem -Path $dir
            Write-Host "Removed empty directory: $dir"
        }
        else {
            Write-Host "Kept $dir because it still contains files:" -ForegroundColor Yellow
            $remaining | ForEach-Object { Write-Host "  $($_.Name)" }
        }
    }
}

if ($RemoveData) {
    foreach ($dataDir in @((Join-Path $env:LOCALAPPDATA "Axiom"), (Join-Path $env:LOCALAPPDATA "Netpetra"))) {
        foreach ($name in @("axiom.db", "axiom.db-wal", "axiom.db-shm", "netpetra.db", "netpetra.db-wal", "netpetra.db-shm")) {
            $path = Join-Path $dataDir $name
            if (Test-Path $path) {
                Remove-SafeItem -Path $path
                Write-Host "Removed data file: $path"
            }
        }

        if (Test-Path $dataDir) {
            $remainingData = @(Get-ChildItem $dataDir -Force)
            if ($remainingData.Count -eq 0) {
                Remove-SafeItem -Path $dataDir
                Write-Host "Removed empty data directory: $dataDir"
            }
        }
    }
}
else {
    Write-Host "Local data was kept at $(Join-Path $env:LOCALAPPDATA 'Axiom'). Use -RemoveData to delete it."
}

Write-Host "Axiom portable installation removed." -ForegroundColor Green
