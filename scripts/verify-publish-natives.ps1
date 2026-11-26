# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Fails when published Windows output contains a native binary whose license is not recorded.

.DESCRIPTION
    Looks at every file in each publish folder, and inside every .NET single-file program. A native
    binary must be listed in packaging/licenses/native-binaries.json and named in
    THIRD_PARTY_NOTICES.md. Files that Microsoft lists under licenses other than MIT may not appear,
    apart from the runtime built into the single-file host. Must stay compatible with Windows
    PowerShell 5.1.
#>
param(
    [Parameter(Mandatory = $true)][string[]]$PublishDir,
    [string]$MapPath,
    [string]$NoticesPath,
    [string]$LibraryLicensePath
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "lib/SingleFileBundle.ps1")
$root = Split-Path -Parent $PSScriptRoot
if (-not $MapPath) { $MapPath = Join-Path $root "packaging/licenses/native-binaries.json" }
if (-not $NoticesPath) { $NoticesPath = Join-Path $root "THIRD_PARTY_NOTICES.md" }
if (-not $LibraryLicensePath) { $LibraryLicensePath = Join-Path $root "packaging/licenses/dotnet/DOTNET-LIBRARY-LICENSE.txt" }

$map = Get-Content -LiteralPath $MapPath -Raw | ConvertFrom-Json
$notices = Get-Content -LiteralPath $NoticesPath -Raw
# https://github.com/dotnet/core/blob/main/license-information-windows.md
$restricted = "DiaSymReader\.Native|PresentationNative_cor3|wpfgfx_cor3|vcruntime140_cor3|D3DCompiler_47_cor3"
$problems = New-Object System.Collections.Generic.List[string]
$seenNative = 0
$seenHosts = 0

function Test-MappedNative([string]$Name, [string]$Where) {
    $entry = @($map.binaries | Where-Object { $_.file -eq $Name })
    if ($entry.Count -eq 0) {
        $problems.Add("Unmapped native binary '$Name' in $Where.")
    }
    elseif (-not $notices.Contains('`' + $Name + '`')) {
        $problems.Add("THIRD_PARTY_NOTICES.md does not name '$Name' (found in $Where).")
    }
}

foreach ($directory in $PublishDir) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Publish folder not found: $directory" }
    $files = @(Get-ChildItem -LiteralPath $directory -File -Recurse)
    if ($files.Count -eq 0) { throw "Publish folder is empty: $directory" }

    foreach ($file in $files) {
        if ($file.Name -match $restricted) { $problems.Add("Restricted-license file '$($file.Name)' in $directory.") }
        if ($file.Name -like "*.deps.json" -and (Get-Content -LiteralPath $file.FullName -Raw) -match $restricted) {
            $problems.Add("$($file.Name) in $directory lists a restricted-license file.")
        }
        if ($file.Length -lt 2) { continue }
        $stream = [System.IO.File]::OpenRead($file.FullName)
        try { $isImage = ($stream.ReadByte() -eq 0x4D) -and ($stream.ReadByte() -eq 0x5A) }
        finally { $stream.Dispose() }
        if (-not $isImage) { continue }

        $bundle = Read-SingleFileBundle -Path $file.FullName
        if ($null -eq $bundle) {
            if (Test-NativeImage ([System.IO.File]::ReadAllBytes($file.FullName))) {
                $seenNative++
                Test-MappedNative $file.Name $directory
            }
            continue
        }

        # The launcher of a single-file program has the .NET runtime, coreclr included, built in.
        $seenHosts++
        if (-not $map.singleFileHost -or -not $notices.Contains($map.singleFileHost.notice)) {
            $problems.Add("$($file.Name) is a single-file program, but the .NET single-file host has no map entry and notice.")
        }
        foreach ($entry in $bundle.Entries) {
            $name = ($entry.Path -split "[\\/]")[-1]
            if ($name -match $restricted) { $problems.Add("Restricted-license file '$name' is packed inside $($file.Name).") }
            if ($name -like "*.deps.json") {
                $deps = [System.Text.Encoding]::UTF8.GetString((Get-BundleEntryBytes $bundle $entry))
                if ($deps -match $restricted) { $problems.Add("$name inside $($file.Name) lists a restricted-license file.") }
            }
            if ($entry.Type -eq 2 -or $name -match "\.(dll|exe)$") {
                if ($entry.Type -eq 2 -or (Test-NativeImage (Get-BundleEntryBytes $bundle $entry))) {
                    $seenNative++
                    Test-MappedNative $name $file.Name
                }
            }
        }
    }
}

if ($seenHosts -gt 0 -and (-not (Test-Path -LiteralPath $LibraryLicensePath -PathType Leaf) -or
        -not (Select-String -LiteralPath $LibraryLicensePath -SimpleMatch "MICROSOFT .NET LIBRARY" -Quiet))) {
    $problems.Add("The .NET Library License text is missing: $LibraryLicensePath")
}
if ($seenHosts + $seenNative -eq 0) { $problems.Add("No native binary was found; refusing to treat the output as checked.") }

if ($problems.Count -gt 0) {
    throw ("Native binary check failed:`n - " + (($problems | Select-Object -Unique) -join "`n - "))
}

Write-Host "Native binary check passed: $seenHosts single-file program(s), $seenNative native binary entries, all recorded." -ForegroundColor Green
