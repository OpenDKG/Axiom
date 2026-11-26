# SPDX-License-Identifier: GPL-3.0-or-later
# Checks that verify-publish-natives.ps1 passes on real publish folders and fails when something is wrong.
param([Parameter(Mandatory = $true)][string[]]$PublishDir)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$verify = Join-Path $PSScriptRoot "verify-publish-natives.ps1"
. (Join-Path $PSScriptRoot "lib/SingleFileBundle.ps1")
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("axiom-natives-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$script:failures = 0

function Assert-Fails([string]$Name, [hashtable]$Arguments, [string]$Expected) {
    try {
        & $verify @Arguments | Out-Null
        Write-Host "FAIL $Name : the check passed"
        $script:failures++
    }
    catch {
        if ($_.Exception.Message.Contains($Expected)) { Write-Host "ok   $Name" }
        else {
            Write-Host "FAIL $Name : unexpected error: $($_.Exception.Message)"
            $script:failures++
        }
    }
}

try {
    & $verify -PublishDir $PublishDir

    $map = Get-Content -LiteralPath (Join-Path $root "packaging/licenses/native-binaries.json") -Raw | ConvertFrom-Json
    $map.binaries = @($map.binaries | Where-Object { $_.file -ne "e_sqlite3.dll" })
    $shortMap = Join-Path $work "map.json"
    $map | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $shortMap -Encoding utf8
    Assert-Fails "a packed library missing from the list" @{ PublishDir = $PublishDir; MapPath = $shortMap } "Unmapped native binary 'e_sqlite3.dll'"

    $notices = [System.IO.File]::ReadAllText((Join-Path $root "THIRD_PARTY_NOTICES.md"))
    $noLibrary = Join-Path $work "notices-library.md"
    [System.IO.File]::WriteAllText($noLibrary, $notices.Replace('`e_sqlite3.dll`', 'removed'))
    Assert-Fails "a library missing from the notices" @{ PublishDir = $PublishDir; NoticesPath = $noLibrary } "does not name 'e_sqlite3.dll'"
    $noHost = Join-Path $work "notices-host.md"
    [System.IO.File]::WriteAllText($noHost, $notices.Replace('.NET single-file host', 'removed'))
    Assert-Fails "the runtime host missing from the notices" @{ PublishDir = $PublishDir; NoticesPath = $noHost } "single-file host has no map entry and notice"

    Assert-Fails "the .NET Library License text missing" @{ PublishDir = $PublishDir; LibraryLicensePath = (Join-Path $work "absent.txt") } "Library License text is missing"

    # A real native image, taken from inside one of the programs.
    $image = $null
    foreach ($program in Get-ChildItem -LiteralPath $PublishDir -File -Recurse -Filter "*.exe") {
        $bundle = Read-SingleFileBundle -Path $program.FullName
        if ($null -eq $bundle) { continue }
        $entry = @($bundle.Entries | Where-Object { $_.Path -eq "e_sqlite3.dll" })
        if ($entry.Count -eq 1) { $image = Get-BundleEntryBytes $bundle $entry[0]; break }
    }
    if ($null -eq $image) { throw "Test setup: no program packs e_sqlite3.dll." }
    foreach ($case in @(
            @{ Name = "a loose native library that is not listed"; File = "unlisted-native.dll"; Expected = "Unmapped native binary 'unlisted-native.dll'" },
            @{ Name = "a loose DiaSymReader"; File = "Microsoft.DiaSymReader.Native.amd64.dll"; Expected = "Restricted-license file" })) {
        $folder = Join-Path $work ([Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $folder | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $folder $case.File), $image)
        Assert-Fails $case.Name @{ PublishDir = @($PublishDir) + $folder } $case.Expected
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { throw "$script:failures native binary check case(s) failed." }
Write-Host "All native binary check cases passed."
