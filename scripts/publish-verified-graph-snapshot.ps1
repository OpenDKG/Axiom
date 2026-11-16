# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Generates, signs, verifies, and publishes the Tier (a) Verified Graph bootstrap snapshot
    to the rolling GitHub Release tag (verified-graph-latest).
#>
[CmdletBinding()]
param(
    [switch]$InitKey,
    [switch]$ForceKey,
    [switch]$DryRun,
    [string]$Repo = 'a-51-50/axiom-verified-graph',
    [string]$Tag = 'verified-graph-latest',
    [string]$KeyPath = $(if ($env:AXIOM_GRAPH_SIGNING_KEY_PATH) { $env:AXIOM_GRAPH_SIGNING_KEY_PATH } else { Join-Path $HOME '.axiom\verified-graph-curator.key.pem' }),
    [string]$BlackboxUrl = 'http://127.0.0.1:9700/',
    [string]$MinClientVersion = '0.54.0',
    [int]$Limit = 500
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$toolProject = Join-Path $repoRoot 'tools\Axiom.GraphSnapshotTool\Axiom.GraphSnapshotTool.csproj'
$outDir = Join-Path $repoRoot 'artifacts\verified-graph'
$snapshotPath = Join-Path $outDir 'verified-graph-snapshot.json'
$checksumPath = $snapshotPath + '.sha256'

function Test-QuietNativeCommand {
    param([scriptblock]$Command)
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $null = & $Command 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        $ErrorActionPreference = $prevPref
    }
}

$dotnet = $null
$dotnetCandidates = @('dotnet')
if ($env:DOTNET_ROOT) { $dotnetCandidates = @((Join-Path $env:DOTNET_ROOT 'dotnet.exe')) + $dotnetCandidates }
$userDotnet = Join-Path $HOME '.dotnet\dotnet.exe'
if (Test-Path $userDotnet) { $dotnetCandidates += $userDotnet }

foreach ($candidate in $dotnetCandidates) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    if (Test-QuietNativeCommand { & $cmd.Source --version }) {
        $dotnet = $cmd.Source
        break
    }
}
if (-not $dotnet) {
    throw '.NET SDK matching global.json is required to run Axiom.GraphSnapshotTool.'
}

if ($InitKey) {
    $cmdArgs = @('run', '--project', $toolProject, '-c', 'Release', '--', 'init-key', '--key-out', $KeyPath)
    if ($ForceKey) {
        $cmdArgs += '--force'
    }
    & $dotnet @cmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Key initialization failed with exit code $LASTEXITCODE."
    }
    Write-Host ''
    Write-Host 'Next step: paste the SPKI public key above into:' -ForegroundColor Cyan
    Write-Host '  src/Axiom.Presentation/VerifiedGraphPeerRelay.cs -> DefaultCuratorPublicKeyDerBase64' -ForegroundColor Yellow
    return
}

if (-not (Test-Path $KeyPath)) {
    throw "Curator signing key not found at '$KeyPath'. Run with -InitKey first."
}

$prevSnapshot = $null
$tempPrevDir = Join-Path ([System.IO.Path]::GetTempPath()) ("axiom-prev-snapshot-" + [guid]::NewGuid().ToString('N'))
try {
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        if (Test-QuietNativeCommand { & gh release view $Tag -R $Repo --json tagName }) {
            New-Item -ItemType Directory -Force -Path $tempPrevDir | Out-Null
            if (Test-QuietNativeCommand { & gh release download $Tag -R $Repo -p 'verified-graph-snapshot.json' -D $tempPrevDir --clobber }) {
                $candidatePrev = Join-Path $tempPrevDir 'verified-graph-snapshot.json'
                if (Test-Path $candidatePrev) {
                    $prevSnapshot = $candidatePrev
                }
            }
        }
    }

    $buildArgs = @(
        'run', '--project', $toolProject, '-c', 'Release', '--',
        'build',
        '--key', $KeyPath,
        '--out', $snapshotPath,
        '--blackbox-url', $BlackboxUrl,
        '--min-client-version', $MinClientVersion,
        '--limit', $Limit.ToString()
    )
    if ($prevSnapshot) {
        $buildArgs += @('--previous-snapshot', $prevSnapshot)
    }

    & $dotnet @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Snapshot build failed with exit code $LASTEXITCODE."
    }
}
finally {
    if (Test-Path $tempPrevDir) {
        Remove-Item $tempPrevDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($DryRun) {
    Write-Host "DryRun complete. Files generated at: $outDir" -ForegroundColor Green
    return
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI (gh) is required to upload release assets. Install gh or pass -DryRun.'
}

if (-not (Test-QuietNativeCommand { & gh release view $Tag -R $Repo })) {
    Write-Host "Creating rolling release tag '$Tag' on $Repo..." -ForegroundColor Cyan
    & gh release create $Tag -R $Repo `
        --title 'Verified Graph Snapshot (Rolling)' `
        --notes 'Automated curator-signed public Verified Graph bootstrap snapshot for Axiom Tier (a) bootstrap cache.' `
        --prerelease
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create GitHub release '$Tag' on $Repo."
    }
}

Write-Host "Uploading snapshot assets to release '$Tag' on $Repo..." -ForegroundColor Cyan
& gh release upload $Tag -R $Repo $snapshotPath $checksumPath --clobber
if ($LASTEXITCODE -ne 0) {
    throw "Failed to upload assets to release '$Tag' on $Repo."
}

Write-Host "Published verified-graph-snapshot.json to $Repo release '$Tag'." -ForegroundColor Green
