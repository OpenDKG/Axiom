# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Builds the core-only Microsoft Store MSIX package and Store upload archive.

.DESCRIPTION
    Publishes the self-contained Desktop and Service executables, stages only the core files,
    writes the package manifest, and packs the result with MakeAppx. The package is intentionally
    unsigned: Microsoft Store signs Store submissions. No certificate, account or upload is used by
    this script.

    The default identity values are placeholders for local inspection. For a real Store submission,
    pass the exact Name, Publisher and PublisherDisplayName values assigned in Partner Center.

.PARAMETER Version
    Release version. Defaults to the Version property in Directory.Build.props.

.PARAMETER IdentityName
    Package Identity Name from Partner Center. Defaults to NETPETRA_STORE_IDENTITY_NAME or Netpetra.

.PARAMETER Publisher
    Package Publisher from Partner Center, including CN=. Defaults to NETPETRA_STORE_PUBLISHER or
    CN=Netpetra.

.PARAMETER PublisherDisplayName
    Publisher display name from Partner Center. Defaults to NETPETRA_STORE_PUBLISHER_DISPLAY_NAME or
    Netpetra.

.PARAMETER OutputDir
    Output directory. Defaults to artifacts\store.

.PARAMETER MakeAppxPath
    Explicit path to makeappx.exe. By default the newest Windows 10/11 SDK x64 copy is used.

.PARAMETER SkipPublish
    Reuse artifacts\msix\publish\desktop and artifacts\msix\publish\service.

.EXAMPLE
    .\scripts\build-msix.ps1

.EXAMPLE
    .\scripts\build-msix.ps1 -IdentityName "12345Publisher.Netpetra" `
        -Publisher "CN=01234567-89ab-cdef-0123-456789abcdef" `
        -PublisherDisplayName "Netpetra"
#>
param(
    [string]$Version = "",
    [string]$IdentityName = $env:NETPETRA_STORE_IDENTITY_NAME,
    [string]$Publisher = $env:NETPETRA_STORE_PUBLISHER,
    [string]$PublisherDisplayName = $env:NETPETRA_STORE_PUBLISHER_DISPLAY_NAME,
    [string]$OutputDir = "",
    [string]$MakeAppxPath = "",
    [switch]$SkipPublish
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $root "artifacts"))

function Resolve-Dotnet {
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

    if (-not $dotnet) { throw "dotnet CLI not found. Install the .NET 10 SDK." }
    return $dotnet
}

function Resolve-MakeAppx {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (-not (Test-Path $ExplicitPath -PathType Leaf)) {
            throw "makeappx.exe not found: $ExplicitPath"
        }
        return (Resolve-Path $ExplicitPath).Path
    }

    $command = Get-Command makeappx.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $kits = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"),
        (Join-Path $env:ProgramFiles "Windows Kits\10\bin")
    ) | Where-Object { Test-Path $_ }

    foreach ($kit in $kits) {
        $candidate = Get-ChildItem $kit -Recurse -Filter makeappx.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\makeappx\.exe$" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }

    throw "makeappx.exe was not found. Install the Windows 10/11 SDK or pass -MakeAppxPath."
}

function Assert-UnderArtifacts {
    param([string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not ($resolved -eq $artifactsRoot -or
              $resolved.StartsWith($artifactsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) {
        throw "Path must stay inside $artifactsRoot : $resolved"
    }
    return $resolved
}

if (-not $Version) {
    $props = Get-Content (Join-Path $root "Directory.Build.props") -Raw
    $match = [regex]::Match($props, "<Version>([^<]+)</Version>")
    if (-not $match.Success) { throw "Could not read Version from Directory.Build.props." }
    $Version = $match.Groups[1].Value.Trim()
}

if ($Version -notmatch "^\d+\.\d+\.\d+(\.\d+)?$") {
    throw "Version must be numeric with two to four parts: $Version"
}

$versionParts = $Version.Split(".")
while ($versionParts.Count -lt 4) {
    $versionParts += "0"
}
$packageVersion = ($versionParts[0..3] -join ".")

if (-not $IdentityName) { $IdentityName = "Netpetra" }
if (-not $Publisher) { $Publisher = "CN=Netpetra" }
if (-not $PublisherDisplayName) { $PublisherDisplayName = "Netpetra" }

if ($IdentityName -eq "Netpetra" -and $Publisher -eq "CN=Netpetra") {
    Write-Warning "Using placeholder package identity. Replace it with the exact Partner Center Name/Publisher values before a Store submission."
}

if ($Publisher -notmatch "^CN=.+") {
    throw "Publisher must be the exact Partner Center value and must start with CN=."
}

if (-not $OutputDir) {
    $OutputDir = Join-Path $root "artifacts\store"
}
$OutputDir = Assert-UnderArtifacts $OutputDir

$dotnet = Resolve-Dotnet
$makeappx = Resolve-MakeAppx $MakeAppxPath
$desktopProject = Join-Path $root "src\Netpetra.Desktop\Netpetra.Desktop.csproj"
$serviceProject = Join-Path $root "src\Netpetra.Service\Netpetra.Service.csproj"
$desktopOut = Join-Path $root "artifacts\msix\publish\desktop"
$serviceOut = Join-Path $root "artifacts\msix\publish\service"
$staging = Join-Path $root "artifacts\msix\staging"
$assets = Join-Path $root "packaging\msix\Assets"
$manifestTemplate = Join-Path $root "packaging\msix\AppxManifest.xml"

if (-not $SkipPublish) {
    Write-Host "Publishing Desktop (win-x64, self-contained)..." -ForegroundColor Cyan
    Remove-Item $desktopOut -Recurse -Force -ErrorAction SilentlyContinue
    & $dotnet publish $desktopProject -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true -p:DebugType=None -p:DebugSymbols=false `
        -o $desktopOut
    if ($LASTEXITCODE -ne 0) { throw "Desktop publish failed with exit code $LASTEXITCODE." }

    Write-Host "Publishing Service (win-x64, self-contained)..." -ForegroundColor Cyan
    Remove-Item $serviceOut -Recurse -Force -ErrorAction SilentlyContinue
    & $dotnet publish $serviceProject -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None -p:DebugSymbols=false -o $serviceOut
    if ($LASTEXITCODE -ne 0) { throw "Service publish failed with exit code $LASTEXITCODE." }
}

$desktopExe = Join-Path $desktopOut "Netpetra.Desktop.exe"
$serviceExe = Join-Path $serviceOut "Netpetra.Service.exe"
if (-not (Test-Path $desktopExe)) { throw "Published Desktop executable not found: $desktopExe" }
if (-not (Test-Path $serviceExe)) { throw "Published Service executable not found: $serviceExe" }

if (-not (Test-Path (Join-Path $assets "StoreLogo.png"))) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "packaging\msix\generate-assets.ps1")
    if ($LASTEXITCODE -ne 0) { throw "MSIX asset generation failed." }
}

Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item $desktopExe (Join-Path $staging "Netpetra.Desktop.exe")
Copy-Item $serviceExe (Join-Path $staging "Netpetra.Service.exe")
Copy-Item $assets (Join-Path $staging "Assets") -Recurse
Copy-Item (Join-Path $desktopOut "community") (Join-Path $staging "community") -Recurse -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root "LICENSE") $staging
Copy-Item (Join-Path $root "NOTICE") $staging
Copy-Item (Join-Path $root "THIRD_PARTY_NOTICES.md") $staging

$manifest = Get-Content $manifestTemplate -Raw
$manifest = $manifest.Replace("__IDENTITY_NAME__", $IdentityName)
$manifest = $manifest.Replace("__PUBLISHER__", $Publisher)
$manifest = $manifest.Replace("__PUBLISHER_DISPLAY_NAME__", $PublisherDisplayName)
$manifest = $manifest.Replace("__VERSION__", $packageVersion)
[IO.File]::WriteAllText(
    (Join-Path $staging "AppxManifest.xml"),
    $manifest,
    (New-Object System.Text.UTF8Encoding -ArgumentList $false))

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$msixName = "Netpetra-$Version-x64.msix"
$msixPath = Join-Path $OutputDir $msixName
$uploadName = "Netpetra-$Version-x64.msixupload"
$uploadPath = Join-Path $OutputDir $uploadName
Remove-Item $msixPath -Force -ErrorAction SilentlyContinue
Remove-Item $uploadPath -Force -ErrorAction SilentlyContinue

Write-Host "Packing MSIX..." -ForegroundColor Cyan
& $makeappx pack /d $staging /p $msixPath /o
if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed with exit code $LASTEXITCODE." }
if (-not (Test-Path $msixPath)) { throw "MSIX was not created: $msixPath" }

# Partner Center accepts an .msixupload container. It is a ZIP containing the .msix and optional
# .appxsym files; this build has no symbols, so the package alone is sufficient.
$temporaryUpload = Join-Path $OutputDir "Netpetra-$Version-x64.upload.zip"
Remove-Item $temporaryUpload -Force -ErrorAction SilentlyContinue
Compress-Archive -Path $msixPath -DestinationPath $temporaryUpload -Force
Move-Item $temporaryUpload $uploadPath -Force

$msixHash = (Get-FileHash $msixPath -Algorithm SHA256).Hash
$uploadHash = (Get-FileHash $uploadPath -Algorithm SHA256).Hash
@(
    "$msixHash  $msixName",
    "$uploadHash  $uploadName"
) | Set-Content (Join-Path $OutputDir "SHA256SUMS.txt") -Encoding ASCII

$info = [ordered]@{
    product = "Netpetra"
    version = $Version
    packageVersion = $packageVersion
    identityName = $IdentityName
    publisher = $Publisher
    publisherDisplayName = $PublisherDisplayName
    identityIsPlaceholder = ($IdentityName -eq "Netpetra" -and $Publisher -eq "CN=Netpetra")
    architecture = "x64"
    package = $msixName
    upload = $uploadName
    signed = "Microsoft Store (not signed by this script)"
    coreOnly = $true
    optionalModules = "excluded"
    agentHooks = "excluded"
    manifest = "packaging\msix\AppxManifest.xml"
}
$info | ConvertTo-Json | Set-Content (Join-Path $OutputDir "package-info.json") -Encoding UTF8

Write-Host "MSIX: $msixPath" -ForegroundColor Green
Write-Host "Store upload: $uploadPath" -ForegroundColor Green
Write-Host "SHA256: $msixHash"
Write-Host "Store will sign the package during submission; this build is unsigned by design." -ForegroundColor Yellow
