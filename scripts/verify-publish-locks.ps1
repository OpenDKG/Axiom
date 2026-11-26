<#
.SYNOPSIS
    Fails when a release publish resolved a package version that CI did not test.

.DESCRIPTION
    Release publishes add a runtime identifier (win-x64, self-contained, single file), which changes
    the restore graph, so they cannot restore in locked mode against the committed
    packages.lock.json files. They write their own lock file to obj/publish.packages.lock.json
    instead. This script compares every such publish lock with the committed lock of the same
    project:

    - a package in both must resolve to the same version;
    - a package in the framework section of the publish lock must already be in the committed lock.

    Packages that appear only in a runtime-specific section (for example "net10.0-windows7.0/win-x64")
    are runtime assets of an already-locked package and are allowed, but still must match a version
    the committed lock pins for the same id.

.PARAMETER Root
    Repository root. Defaults to the parent of this script's directory.
#>
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

function Get-LockPackages([object]$section) {
    $packages = @{}
    if ($null -eq $section) { return $packages }
    foreach ($property in $section.PSObject.Properties) {
        $entry = $property.Value
        if ($entry.type -eq 'Project' -or -not $entry.resolved) { continue }
        $packages[$property.Name.ToLowerInvariant()] = [string]$entry.resolved
    }
    return $packages
}

$publishLocks = Get-ChildItem -Path (Join-Path $Root 'src') -Recurse -File -Filter 'publish.packages.lock.json' |
    Where-Object { $_.Directory.Name -eq 'obj' }
if (-not $publishLocks) {
    throw 'No obj/publish.packages.lock.json was found. Run the release publish first.'
}

$problems = New-Object System.Collections.Generic.List[string]
foreach ($publishLock in $publishLocks) {
    $projectDir = $publishLock.Directory.Parent.FullName
    $committedPath = Join-Path $projectDir 'packages.lock.json'
    $project = Split-Path -Leaf $projectDir
    if (-not (Test-Path -LiteralPath $committedPath)) {
        $problems.Add("${project}: publish restored packages but there is no committed packages.lock.json")
        continue
    }

    $published = (Get-Content -Raw -LiteralPath $publishLock.FullName | ConvertFrom-Json).dependencies
    $committed = (Get-Content -Raw -LiteralPath $committedPath | ConvertFrom-Json).dependencies

    # Every version the committed lock pins for a package id, across all of its sections.
    $pinned = @{}
    foreach ($section in $committed.PSObject.Properties) {
        $packages = Get-LockPackages $section.Value
        foreach ($id in $packages.Keys) {
            if (-not $pinned.ContainsKey($id)) { $pinned[$id] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$pinned[$id].Add($packages[$id])
        }
    }

    foreach ($section in $published.PSObject.Properties) {
        $runtimeSpecific = $section.Name.Contains('/')
        $packages = Get-LockPackages $section.Value
        foreach ($id in $packages.Keys) {
            $version = $packages[$id]
            if ($pinned.ContainsKey($id)) {
                if (-not $pinned[$id].Contains($version)) {
                    $problems.Add("${project} [$($section.Name)]: $id resolved $version, committed lock pins $([string]::Join(', ', $pinned[$id]))")
                }
            }
            elseif (-not $runtimeSpecific) {
                $problems.Add("${project} [$($section.Name)]: $id $version is not in the committed lock")
            }
        }
    }
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    throw "Release publish resolved $($problems.Count) package version(s) that the locked CI restore did not test."
}

Write-Host "Publish package versions match the committed lock files ($($publishLocks.Count) project(s))." -ForegroundColor Green
