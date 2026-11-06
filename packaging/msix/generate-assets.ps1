# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Generates the MSIX and Microsoft Store image assets from the Axiom icon and lockup.
#>
param(
    [string]$SourceIcon = "",
    [string]$SourceLockup = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $SourceIcon) {
    $SourceIcon = Join-Path $root "src\Netpetra.UI\Resources\axiom-icon.png"
}
if (-not $SourceLockup) {
    $SourceLockup = Join-Path $root "src\Netpetra.UI\Resources\axiom-lockup.png"
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot "Assets"
}
if (-not (Test-Path $SourceIcon)) {
    throw "Source icon not found: $SourceIcon"
}
if (-not (Test-Path $SourceLockup)) {
    throw "Source lockup not found: $SourceLockup"
}

Add-Type -AssemblyName System.Drawing

$icon = [System.Drawing.Image]::FromFile($SourceIcon)
$lockup = [System.Drawing.Image]::FromFile($SourceLockup)
$background = [System.Drawing.ColorTranslator]::FromHtml("#0B0F14")

function New-Asset {
    param(
        [int]$Width,
        [int]$Height,
        [string]$Name,
        [bool]$DarkBackground,
        [bool]$UseLockup
    )

    $image = if ($UseLockup) { $lockup } else { $icon }
    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear($(if ($DarkBackground) { $background } else { [System.Drawing.Color]::Transparent }))

    $padding = if ($UseLockup) { 0.90 } else { 0.86 }
    $scale = [Math]::Min($Width / $image.Width, $Height / $image.Height) * $padding
    $drawWidth = [Math]::Max(1, [int]($image.Width * $scale))
    $drawHeight = [Math]::Max(1, [int]($image.Height * $scale))
    $x = [int](($Width - $drawWidth) / 2)
    $y = [int](($Height - $drawHeight) / 2)
    $graphics.DrawImage($image, $x, $y, $drawWidth, $drawHeight)

    $path = Join-Path $OutputDir $Name
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    Write-Host "Wrote $path"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

New-Asset -Width 50 -Height 50 -Name "StoreLogo.png" -DarkBackground $false -UseLockup $false
New-Asset -Width 44 -Height 44 -Name "Square44x44Logo.png" -DarkBackground $false -UseLockup $false
New-Asset -Width 71 -Height 71 -Name "Square71x71Logo.png" -DarkBackground $false -UseLockup $false
New-Asset -Width 150 -Height 150 -Name "Square150x150Logo.png" -DarkBackground $false -UseLockup $false
New-Asset -Width 310 -Height 310 -Name "Square310x310Logo.png" -DarkBackground $true -UseLockup $false
New-Asset -Width 310 -Height 150 -Name "Wide310x150Logo.png" -DarkBackground $true -UseLockup $true
New-Asset -Width 620 -Height 300 -Name "SplashScreen.png" -DarkBackground $true -UseLockup $true

$icon.Dispose()
$lockup.Dispose()
