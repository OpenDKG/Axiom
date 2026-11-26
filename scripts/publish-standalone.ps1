<#
.SYNOPSIS
    Publishes the standalone (self-contained) Windows x64 shell.

.DESCRIPTION
    Produces a single Axiom.Desktop.exe (Avalonia Windows host) that runs without a .NET runtime
    installed. The output lands in artifacts\publish\win-x64 by default.

.PARAMETER Output
    Optional output directory; defaults to the publish profile value.

.EXAMPLE
    .\scripts\publish-standalone.ps1

.EXAMPLE
    .\scripts\publish-standalone.ps1 -Output D:\Dist\Axiom
#>
param(
    [string]$Output
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root "src\Axiom.Desktop.Avalonia.Windows\Axiom.Desktop.Avalonia.Windows.csproj"

$arguments = @(
    "publish", $project,
    "-c", "Release",
    "-p:PublishProfile=win-x64-selfcontained",
    "-p:RestoreLockedMode=false",
    "-p:RestorePackagesWithLockFile=true",
    "-p:NuGetLockFilePath=obj/publish.packages.lock.json"
)

if ($Output) {
    $arguments += @("-o", $Output)
}

Write-Host "Publishing standalone win-x64 build..." -ForegroundColor Cyan
$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if ($dotnet) {
    $sdks = & $dotnet --list-sdks 2>$null
    if (-not $sdks) { $dotnet = $null }
}

if (-not $dotnet) {
    foreach ($candidate in @(
        (Join-Path $env:USERPROFILE ".dotnet-sdk\dotnet.exe"),
        (Join-Path $env:USERPROFILE ".dotnet\dotnet.exe")
    )) {
        if (Test-Path $candidate) { $dotnet = $candidate; break }
    }
}

if (-not $dotnet) { throw "dotnet CLI not found. Install the .NET 10 SDK pinned in global.json." }

# Publish locks from an earlier run would be checked as if they came from this one.
Get-ChildItem -Path (Join-Path $root "src") -Recurse -File -Filter "publish.packages.lock.json" |
    Where-Object { $_.Directory.Name -eq "obj" } | Remove-Item -Force

& $dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

# Runtime-specific publishes cannot restore in locked mode; prove they resolved the tested versions.
& (Join-Path $PSScriptRoot "verify-publish-locks.ps1") -Root $root

if (-not $Output) {
    $Output = Join-Path $root "artifacts\publish\win-x64"
}

$exe = Join-Path $Output "Axiom.Desktop.exe"
if (-not (Test-Path $exe)) { throw "Expected executable not found: $exe" }

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Done: $exe ($size MB, self-contained single file)" -ForegroundColor Green
