# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Generates the MSIX and Microsoft Store image assets from the application icon.
#>
param(
    [string]$SourceIcon = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $SourceIcon) {
    $SourceIcon = Join-Path $root "src\Netpetra.UI\Resources\netpetra-icon.png"
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot "Assets"
}
if (-not (Test-Path $SourceIcon)) {
    throw "Source icon not found: $SourceIcon"
}

Add-Type -AssemblyName System.Drawing

$source = [System.Drawing.Image]::FromFile($SourceIcon)
$background = [System.Drawing.ColorTranslator]::FromHtml("#0B0F14")

function New-Asset {
    param(
        [int]$Width,
        [int]$Height,
        [string]$Name,
        [bool]$DarkBackground,
        [bool]$Wordmark
    )

    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.Clear($(if ($DarkBackground) { $background } else { [System.Drawing.Color]::Transparent }))

    $wordmarkWidth = if ($Wordmark) { [Math]::Max(0, [int]($Width * 0.52)) } else { 0 }
    $availableWidth = $Width - $wordmarkWidth
    $availableHeight = $Height
    $scale = [Math]::Min($availableWidth / $source.Width, $availableHeight / $source.Height) * 0.76
    $drawWidth = [Math]::Max(1, [int]($source.Width * $scale))
    $drawHeight = [Math]::Max(1, [int]($source.Height * $scale))
    $x = [int](($availableWidth - $drawWidth) / 2)
    $y = [int](($availableHeight - $drawHeight) / 2)
    $graphics.DrawImage($source, $x, $y, $drawWidth, $drawHeight)

    if ($Wordmark) {
        $fontSize = [Math]::Max(11, [int]($Height * 0.16))
        $font = New-Object System.Drawing.Font("Segoe UI Semibold", $fontSize, [System.Drawing.FontStyle]::Bold)
        $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $format = New-Object System.Drawing.StringFormat
        $format.Alignment = [System.Drawing.StringAlignment]::Near
        $format.LineAlignment = [System.Drawing.StringAlignment]::Center
        $graphics.DrawString(
            "NETPETRA",
            $font,
            $brush,
            [float]($availableWidth + [Math]::Max(4, [int]($Width * 0.02))),
            [float]($Height / 2),
            $format)
        $font.Dispose()
        $brush.Dispose()
        $format.Dispose()
    }

    $path = Join-Path $OutputDir $Name
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    Write-Host "Wrote $path"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

New-Asset -Width 50 -Height 50 -Name "StoreLogo.png" -DarkBackground $false -Wordmark $false
New-Asset -Width 44 -Height 44 -Name "Square44x44Logo.png" -DarkBackground $false -Wordmark $false
New-Asset -Width 71 -Height 71 -Name "Square71x71Logo.png" -DarkBackground $false -Wordmark $false
New-Asset -Width 150 -Height 150 -Name "Square150x150Logo.png" -DarkBackground $false -Wordmark $false
New-Asset -Width 310 -Height 310 -Name "Square310x310Logo.png" -DarkBackground $true -Wordmark $false
New-Asset -Width 310 -Height 150 -Name "Wide310x150Logo.png" -DarkBackground $true -Wordmark $true
New-Asset -Width 620 -Height 300 -Name "SplashScreen.png" -DarkBackground $true -Wordmark $true

$source.Dispose()
