# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Installs Axiom as a per-user portable application.

.DESCRIPTION
    Copies the published Axiom.Desktop.exe and Axiom.Service.exe into
    %LOCALAPPDATA%\Programs\Axiom, writes a small install manifest with their SHA-256 hashes,
    and creates a Start Menu shortcut. No administrator rights, Windows service registration,
    firewall changes or network access are required.

.PARAMETER Source
    Path to Axiom.Desktop.exe. Defaults to the standalone build in artifacts\publish\win-x64.

.PARAMETER ServiceSource
    Path to Axiom.Service.exe. Defaults to artifacts\publish\service.

.PARAMETER InstallDir
    Target directory. Defaults to %LOCALAPPDATA%\Programs\Axiom.

.PARAMETER NoShortcut
    Skip the Start Menu shortcut.

.EXAMPLE
    .\scripts\install-portable.ps1

.EXAMPLE
    .\scripts\install-portable.ps1 -Source D:\Dist\Axiom.Desktop.exe -NoShortcut
#>
param(
    [string]$Source = "",
    [string]$ServiceSource = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Axiom"),
    [switch]$NoShortcut
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

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

if (Test-ReparsePath $InstallDir) {
    throw "Install location contains a junction or symbolic link: $InstallDir"
}

if (-not $Source) {
    $Source = Join-Path $root "artifacts\publish\win-x64\Axiom.Desktop.exe"
}

if (-not $ServiceSource) {
    $candidate = Join-Path (Split-Path $Source -Parent) "Axiom.Service.exe"
    if (Test-Path $candidate) {
        $ServiceSource = $candidate
    }
    else {
        $ServiceSource = Join-Path $root "artifacts\publish\service\Axiom.Service.exe"
    }
}

if (-not (Test-Path $Source -PathType Leaf)) {
    throw "Axiom.Desktop.exe was not found at '$Source'. Run .\scripts\publish-standalone.ps1 first or pass -Source."
}

$hasService = Test-Path $ServiceSource -PathType Leaf
if (-not $hasService) {
    Write-Warning "Axiom.Service.exe was not found at '$ServiceSource'. Installing the desktop in-process mode only."
}

$legacyProcesses = Get-Process -Name "Axiom.Desktop","Axiom.Service","Netpetra.Desktop","Netpetra.Service" -ErrorAction SilentlyContinue
if ($legacyProcesses) {
    throw "Axiom is running. Close it before installing."
}

$sourceItem = Get-Item $Source
$hash = (Get-FileHash $sourceItem.FullName -Algorithm SHA256).Hash
$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($sourceItem.FullName).ProductVersion
if ([string]::IsNullOrWhiteSpace($version)) {
    $version = "0.0.0"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$target = Join-Path $InstallDir "Axiom.Desktop.exe"
Copy-Item $sourceItem.FullName $target -Force

$communitySource = Join-Path (Split-Path -Parent $sourceItem.FullName) "community"
if (Test-Path (Join-Path $communitySource "feed.json")) {
    Copy-Item $communitySource $InstallDir -Recurse -Force
}

$serviceHash = $null
$serviceTarget = Join-Path $InstallDir "Axiom.Service.exe"
if ($hasService) {
    $serviceHash = (Get-FileHash $ServiceSource -Algorithm SHA256).Hash
    Copy-Item $ServiceSource $serviceTarget -Force
}

$manifest = [ordered]@{
    product        = "Axiom"
    version        = $version
    sha256         = $hash
    serviceSha256  = $serviceHash
    installedUtc   = (Get-Date).ToUniversalTime().ToString("O")
    source         = $sourceItem.FullName
}
$manifest | ConvertTo-Json | Set-Content (Join-Path $InstallDir "install.json") -Encoding UTF8

if (-not $NoShortcut) {
    $startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
    $shortcutPath = Join-Path $startMenu "Axiom.lnk"
    $legacyShortcutPath = Join-Path $startMenu "Netpetra.lnk"
    if (Test-Path $legacyShortcutPath) {
        Remove-Item -LiteralPath $legacyShortcutPath -Force
    }

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $target
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "Axiom - Open-Source Firewall & Security Monitor"
    $shortcut.Save()

    Write-Host "Start Menu shortcut: $shortcutPath"
}

Write-Host "Installed Axiom $version" -ForegroundColor Green
Write-Host "  executable: $target"
Write-Host "  sha256:     $hash"
if ($hasService) {
    Write-Host "  service:    $serviceTarget (run manually; not registered)"
    Write-Host "  service sha256: $serviceHash"
}
# Migrate the legacy executable/shortcut names. User data is handled by the app.
$legacyInstallDir = Join-Path $env:LOCALAPPDATA "Programs\Netpetra"
if (Test-Path $legacyInstallDir) {
    foreach ($legacyFile in @("Netpetra.Desktop.exe", "Netpetra.Service.exe", "install.json", "Axiom.Desktop.exe", "Axiom.Service.exe")) {
        $candidate = Join-Path $legacyInstallDir $legacyFile
        if (Test-Path $candidate) { Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue }
    }
    $legacyCommunity = Join-Path $legacyInstallDir "community"
    if (Test-Path $legacyCommunity) {
        $legacyRemaining = @(Get-ChildItem $legacyCommunity -Force -ErrorAction SilentlyContinue)
        $legacyOnlyFeed = $legacyRemaining.Count -le 1 -and ($legacyRemaining.Count -eq 0 -or $legacyRemaining[0].Name -eq "feed.json")
        if ($legacyOnlyFeed) { Remove-Item -LiteralPath $legacyCommunity -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $remaining = @(Get-ChildItem $legacyInstallDir -Force -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $legacyInstallDir -Force -ErrorAction SilentlyContinue }
}
$legacyRunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path $legacyRunKey -Name "Netpetra" -ErrorAction SilentlyContinue
Write-Host "  data:       $(Join-Path $env:LOCALAPPDATA 'Axiom') (migrated by the app; legacy data is preserved if migration cannot move it)"
Write-Host "No administrator rights, Windows service registration or firewall rule were used."
