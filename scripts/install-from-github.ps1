# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Downloads, verifies and installs the latest Netpetra release for the current user.

.DESCRIPTION
    Fetches the GitHub release asset and SHA256SUMS.txt, verifies the archive, extracts it, runs the
    portable installer and optionally launches Netpetra. No administrator rights, service
    registration or firewall change is performed.

.PARAMETER Version
    Release tag without the leading v (for example 0.4.0). Defaults to the latest release.

.PARAMETER InstallDir
    Target directory. Defaults to %LOCALAPPDATA%\Programs\Netpetra.

.PARAMETER NoLaunch
    Install without starting the desktop.

.EXAMPLE
    irm https://raw.githubusercontent.com/a-51-50/Netpetra/main/scripts/install-from-github.ps1 | iex

.EXAMPLE
    .\install-from-github.ps1 -Version 0.4.0 -NoLaunch
#>
param(
    [string]$Version = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Netpetra"),
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"
$repo = "a-51-50/Netpetra"
$headers = @{ "User-Agent" = "Netpetra-Installer" }

$releaseUri = if ($Version) {
    "https://api.github.com/repos/$repo/releases/tags/v$Version"
}
else {
    "https://api.github.com/repos/$repo/releases/latest"
}

Write-Host "Reading Netpetra release metadata..." -ForegroundColor Cyan
$release = Invoke-RestMethod -Uri $releaseUri -Headers $headers

$zipAsset = $release.assets | Where-Object { $_.name -like "Netpetra-*-win-x64.zip" } | Select-Object -First 1
$sumAsset = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1
if (-not $zipAsset -or -not $sumAsset) {
    throw "The release does not contain the expected Netpetra archive and SHA256SUMS.txt."
}

$temp = Join-Path $env:TEMP ("netpetra-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    $zipPath = Join-Path $temp $zipAsset.name
    $sumPath = Join-Path $temp "SHA256SUMS.txt"

    Write-Host "Downloading $($zipAsset.name)..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri $zipAsset.browser_download_url -OutFile $zipPath
    Invoke-WebRequest -UseBasicParsing -Uri $sumAsset.browser_download_url -OutFile $sumPath

    $line = Get-Content $sumPath | Where-Object { $_ -match [regex]::Escape($zipAsset.name) } | Select-Object -First 1
    if (-not $line) {
        throw "SHA256SUMS.txt does not contain $($zipAsset.name)."
    }

    $expected = ($line -split "\s+")[0].ToUpperInvariant()
    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch. Expected $expected, got $actual."
    }

    Write-Host "Checksum verified." -ForegroundColor Green
    Expand-Archive -Path $zipPath -DestinationPath $temp -Force

    $desktop = Join-Path $temp "Netpetra.Desktop.exe"
    $installer = Join-Path $temp "install-portable.ps1"
    if (-not (Test-Path $desktop) -or -not (Test-Path $installer)) {
        throw "The archive is incomplete."
    }

    & $installer -Source $desktop -InstallDir $InstallDir

    if (-not $NoLaunch) {
        $installed = Join-Path $InstallDir "Netpetra.Desktop.exe"
        Start-Process -FilePath $installed
        Write-Host "Started Netpetra." -ForegroundColor Green
    }
}
finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}
