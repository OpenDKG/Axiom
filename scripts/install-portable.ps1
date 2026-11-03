# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Installs Netrigil as a per-user portable application.

.DESCRIPTION
    Copies the published Netrigil.Desktop.exe into %LOCALAPPDATA%\Programs\Netrigil, writes a
    small install manifest with the SHA-256, and creates a Start Menu shortcut. No administrator
    rights, no Windows service, no firewall changes and no network access are required.

.PARAMETER Source
    Path to Netrigil.Desktop.exe. Defaults to the standalone build in artifacts\publish\win-x64.

.PARAMETER InstallDir
    Target directory. Defaults to %LOCALAPPDATA%\Programs\Netrigil.

.PARAMETER NoShortcut
    Skip the Start Menu shortcut.

.EXAMPLE
    .\scripts\install-portable.ps1

.EXAMPLE
    .\scripts\install-portable.ps1 -Source D:\Dist\Netrigil.Desktop.exe -NoShortcut
#>
param(
    [string]$Source = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Netrigil"),
    [switch]$NoShortcut
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $Source) {
    $Source = Join-Path $root "artifacts\publish\win-x64\Netrigil.Desktop.exe"
}

if (-not (Test-Path $Source -PathType Leaf)) {
    throw "Netrigil.Desktop.exe was not found at '$Source'. Run .\scripts\publish-standalone.ps1 first or pass -Source."
}

if (Get-Process -Name "Netrigil.Desktop" -ErrorAction SilentlyContinue) {
    throw "Netrigil is running. Close it before installing."
}

$sourceItem = Get-Item $Source
$hash = (Get-FileHash $sourceItem.FullName -Algorithm SHA256).Hash
$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($sourceItem.FullName).ProductVersion
if ([string]::IsNullOrWhiteSpace($version)) {
    $version = "0.0.0"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$target = Join-Path $InstallDir "Netrigil.Desktop.exe"
Copy-Item $sourceItem.FullName $target -Force

$manifest = [ordered]@{
    product      = "Netrigil"
    version      = $version
    sha256       = $hash
    installedUtc = (Get-Date).ToUniversalTime().ToString("O")
    source       = $sourceItem.FullName
}
$manifest | ConvertTo-Json | Set-Content (Join-Path $InstallDir "install.json") -Encoding UTF8

if (-not $NoShortcut) {
    $startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
    $shortcutPath = Join-Path $startMenu "Netrigil.lnk"

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $target
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "Netrigil - Open-Source Firewall & Security Monitor"
    $shortcut.Save()

    Write-Host "Start Menu shortcut: $shortcutPath"
}

Write-Host "Installed Netrigil $version" -ForegroundColor Green
Write-Host "  executable: $target"
Write-Host "  sha256:     $hash"
Write-Host "  data:       $(Join-Path $env:LOCALAPPDATA 'Netrigil') (created by the service)"
Write-Host "No administrator rights, service or firewall rule were used."
