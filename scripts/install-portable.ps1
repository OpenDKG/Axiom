# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Installs Axiom as a per-user portable application.

.DESCRIPTION
    Copies the published Netpetra.Desktop.exe and Netpetra.Service.exe into
    %LOCALAPPDATA%\Programs\Netpetra, writes a small install manifest with their SHA-256 hashes,
    and creates a Start Menu shortcut. No administrator rights, Windows service registration,
    firewall changes or network access are required.

.PARAMETER Source
    Path to Netpetra.Desktop.exe. Defaults to the standalone build in artifacts\publish\win-x64.

.PARAMETER ServiceSource
    Path to Netpetra.Service.exe. Defaults to artifacts\publish\service.

.PARAMETER InstallDir
    Target directory. Defaults to %LOCALAPPDATA%\Programs\Netpetra.

.PARAMETER NoShortcut
    Skip the Start Menu shortcut.

.EXAMPLE
    .\scripts\install-portable.ps1

.EXAMPLE
    .\scripts\install-portable.ps1 -Source D:\Dist\Netpetra.Desktop.exe -NoShortcut
#>
param(
    [string]$Source = "",
    [string]$ServiceSource = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Netpetra"),
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
    $Source = Join-Path $root "artifacts\publish\win-x64\Netpetra.Desktop.exe"
}

if (-not $ServiceSource) {
    $candidate = Join-Path (Split-Path $Source -Parent) "Netpetra.Service.exe"
    if (Test-Path $candidate) {
        $ServiceSource = $candidate
    }
    else {
        $ServiceSource = Join-Path $root "artifacts\publish\service\Netpetra.Service.exe"
    }
}

if (-not (Test-Path $Source -PathType Leaf)) {
    throw "Netpetra.Desktop.exe was not found at '$Source'. Run .\scripts\publish-standalone.ps1 first or pass -Source."
}

$hasService = Test-Path $ServiceSource -PathType Leaf
if (-not $hasService) {
    Write-Warning "Netpetra.Service.exe was not found at '$ServiceSource'. Installing the desktop in-process mode only."
}

if (Get-Process -Name "Netpetra.Desktop","Netpetra.Service" -ErrorAction SilentlyContinue) {
    throw "Axiom is running. Close it before installing."
}

$sourceItem = Get-Item $Source
$hash = (Get-FileHash $sourceItem.FullName -Algorithm SHA256).Hash
$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($sourceItem.FullName).ProductVersion
if ([string]::IsNullOrWhiteSpace($version)) {
    $version = "0.0.0"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$target = Join-Path $InstallDir "Netpetra.Desktop.exe"
Copy-Item $sourceItem.FullName $target -Force

$communitySource = Join-Path (Split-Path -Parent $sourceItem.FullName) "community"
if (Test-Path (Join-Path $communitySource "feed.json")) {
    Copy-Item $communitySource $InstallDir -Recurse -Force
}

$serviceHash = $null
$serviceTarget = Join-Path $InstallDir "Netpetra.Service.exe"
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
Write-Host "  data:       $(Join-Path $env:LOCALAPPDATA 'Netpetra') (created by the service)"
Write-Host "No administrator rights, Windows service registration or firewall rule were used."
