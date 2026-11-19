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
    Target directory. Defaults to %LOCALAPPDATA%\Programs\Axiom.

.PARAMETER NoLaunch
    Install without starting the desktop.

.PARAMETER Repository
    GitHub repository to install from, as owner/name. Defaults to the public OpenDKG/Axiom.

.PARAMETER Token
    Optional GitHub token for a private repository. When omitted for a private repository, the
    installer reads AXIOM_GITHUB_TOKEN, NETPETRA_GITHUB_TOKEN, GH_TOKEN or GITHUB_TOKEN. Tokens are
    never sent to the public OpenDKG/Axiom endpoints unless you pass -Token explicitly. Never pass a
    token on a shared command line.

.PARAMETER PublicRelease
    Download from the OpenDKG public releases without using GitHub credentials. Kept for backwards
    compatibility; it forces the repository to OpenDKG/Axiom and ignores any token.

.EXAMPLE
    irm https://raw.githubusercontent.com/OpenDKG/Axiom/main/scripts/install-from-github.ps1 | iex

.EXAMPLE
    .\install-from-github.ps1 -Version 0.4.0 -NoLaunch

.EXAMPLE
    # Private upstream repository: reuse an authenticated GitHub CLI session.
    $env:AXIOM_GITHUB_TOKEN = gh auth token
    .\install-from-github.ps1 -Repository a-51-50/Axiom
#>
param(
    [string]$Version = "",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Axiom"),
    [switch]$NoLaunch,
    [string]$Token = "",
    [switch]$PublicRelease,
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository = "OpenDKG/Axiom"
)

$ErrorActionPreference = "Stop"
$repo = if ($PublicRelease) { "OpenDKG/Axiom" } else { $Repository }
$isPublicRepository = $repo -eq "OpenDKG/Axiom"
$headers = @{
    "User-Agent" = "Axiom-Installer"
    "Accept" = "application/vnd.github+json"
}

$tokenValue = if ($PublicRelease -or ($isPublicRepository -and -not $PSBoundParameters.ContainsKey("Token"))) {
    # Never forward ambient credentials to the public repository's endpoints.
    ""
}
elseif (-not [string]::IsNullOrWhiteSpace($Token)) {
    $Token
}
elseif (-not [string]::IsNullOrWhiteSpace($env:AXIOM_GITHUB_TOKEN)) {
    $env:AXIOM_GITHUB_TOKEN
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
    if ($PublicRelease -or $isPublicRepository) {
        throw "Could not read the public OpenDKG release metadata. $($_.Exception.Message)"
    }
    throw "Could not read release metadata. If the repository is private, set AXIOM_GITHUB_TOKEN (for example: `$env:AXIOM_GITHUB_TOKEN = gh auth token). $($_.Exception.Message)"
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

$temp = Join-Path $env:TEMP ("axiom-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    if ([IO.Path]::GetFileName($zipAsset.name) -ne $zipAsset.name) {
        throw "The release archive name is not a plain file name: $($zipAsset.name)"
    }

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

    # Match the whole line so a shorter asset name cannot match inside a longer one.
    $sumPattern = "^\s*([0-9a-fA-F]{64})\s+\*?" + [regex]::Escape($zipAsset.name) + "\s*$"
    $sumMatch = Get-Content $sumPath | ForEach-Object { [regex]::Match($_, $sumPattern) } |
        Where-Object { $_.Success } | Select-Object -First 1
    if (-not $sumMatch) {
        throw "SHA256SUMS.txt does not contain a valid entry for $($zipAsset.name)."
    }

    $expected = $sumMatch.Groups[1].Value.ToUpperInvariant()
    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch. Expected $expected, got $actual."
    }

    Write-Host "Checksum verified." -ForegroundColor Green
    Expand-Archive -Path $zipPath -DestinationPath $temp -Force

    $desktop = Join-Path $temp "Axiom.Desktop.exe"
    $installer = Join-Path $temp "install-portable.ps1"
    if (-not (Test-Path $desktop) -or -not (Test-Path $installer)) {
        throw "The archive is incomplete."
    }

    & $installer -Source $desktop -InstallDir $InstallDir

    if (-not $NoLaunch) {
        $installed = Join-Path $InstallDir "Axiom.Desktop.exe"
        Start-Process -FilePath $installed
        Write-Host "Started Axiom." -ForegroundColor Green
    }
}
finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}
