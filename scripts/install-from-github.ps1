# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Downloads, verifies and installs the latest Axiom release for the current user.

.DESCRIPTION
    Fetches the GitHub release asset and SHA256SUMS.txt, verifies the archive, extracts it, runs the
    portable installer and optionally launches Axiom. No administrator rights, service
    registration or firewall change is performed.

.PARAMETER Version
    Release tag without the leading v (for example 0.4.0). Defaults to the latest release.

.PARAMETER InstallDir
    Target directory. Defaults to %LOCALAPPDATA%\Programs\Netpetra.

.PARAMETER NoLaunch
    Install without starting the desktop.

.PARAMETER Token
    Optional GitHub token for a private repository. When omitted, the installer reads
    NETPETRA_GITHUB_TOKEN, GH_TOKEN or GITHUB_TOKEN. Never pass a token on a shared command line.

.EXAMPLE
    irm https://raw.githubusercontent.com/a-51-50/Axiom/main/scripts/install-from-github.ps1 | iex

.EXAMPLE
    .\install-from-github.ps1 -Version 0.4.0 -NoLaunch

.EXAMPLE
    # Private repository: reuse an authenticated GitHub CLI session.
    $env:NETPETRA_GITHUB_TOKEN = gh auth token
    .\install-from-github.ps1
#>
param(
    [string]$Version = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Netpetra"),
    [switch]$NoLaunch,
    [string]$Token = ""
)

$ErrorActionPreference = "Stop"
$repo = "a-51-50/Axiom"
$headers = @{
    "User-Agent" = "Axiom-Installer"
    "Accept" = "application/vnd.github+json"
}

$tokenValue = if (-not [string]::IsNullOrWhiteSpace($Token)) {
    $Token
}
elseif (-not [string]::IsNullOrWhiteSpace($env:NETPETRA_GITHUB_TOKEN)) {
    $env:NETPETRA_GITHUB_TOKEN
}
elseif (-not [string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
    $env:GH_TOKEN
}
else {
    $env:GITHUB_TOKEN
}

$usingToken = -not [string]::IsNullOrWhiteSpace($tokenValue)
if ($usingToken) {
    $headers["Authorization"] = "Bearer $tokenValue"
}

$releaseUri = if ($Version) {
    "https://api.github.com/repos/$repo/releases/tags/v$Version"
}
else {
    "https://api.github.com/repos/$repo/releases/latest"
}

Write-Host "Reading Axiom release metadata..." -ForegroundColor Cyan
try {
    $release = Invoke-RestMethod -Uri $releaseUri -Headers $headers
}
catch {
    throw "Could not read release metadata. If the repository is private, set NETPETRA_GITHUB_TOKEN (for example: `$env:NETPETRA_GITHUB_TOKEN = gh auth token). $($_.Exception.Message)"
}

$zipAsset = $release.assets | Where-Object { $_.name -like "Axiom-*-win-x64.zip" } | Select-Object -First 1
if (-not $zipAsset) {
    # Compatibility bridge for releases published before the public Axiom rename.
    $zipAsset = $release.assets | Where-Object { $_.name -like "Netpetra-*-win-x64.zip" } | Select-Object -First 1
    if ($zipAsset) {
        Write-Warning "Using the legacy Netpetra archive from this release. A newer Axiom-named release is preferred."
    }
}
$sumAsset = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1
if (-not $zipAsset -or -not $sumAsset) {
    throw "The release does not contain an Axiom archive (or legacy Netpetra archive) and SHA256SUMS.txt."
}

$temp = Join-Path $env:TEMP ("netpetra-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    $zipPath = Join-Path $temp $zipAsset.name
    $sumPath = Join-Path $temp "SHA256SUMS.txt"

    $assetHeaders = $headers.Clone()
    if ($usingToken) {
        # Private release assets are downloaded through the API asset URL.
        $assetHeaders["Accept"] = "application/octet-stream"
    }

    $zipUri = if ($usingToken) { $zipAsset.url } else { $zipAsset.browser_download_url }
    $sumUri = if ($usingToken) { $sumAsset.url } else { $sumAsset.browser_download_url }

    Write-Host "Downloading $($zipAsset.name)..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri $zipUri -Headers $assetHeaders -OutFile $zipPath
    Invoke-WebRequest -UseBasicParsing -Uri $sumUri -Headers $assetHeaders -OutFile $sumPath

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
        Write-Host "Started Axiom." -ForegroundColor Green
    }
}
finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}
