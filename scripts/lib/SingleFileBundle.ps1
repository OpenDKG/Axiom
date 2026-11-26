# SPDX-License-Identifier: GPL-3.0-or-later
# Reads what a .NET single-file program contains, without running it.
# Must stay compatible with Windows PowerShell 5.1.

function Test-NativeImage {
    # True for a Windows program or library without a .NET (CLR) header.
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 64 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $false }
    $pe = [System.BitConverter]::ToInt32($Bytes, 0x3C)
    if ($pe -lt 0 -or $pe + 26 -gt $Bytes.Length) { return $false }
    $optional = $pe + 24
    $directories = $optional + 96
    if ([System.BitConverter]::ToUInt16($Bytes, $optional) -eq 0x20B) { $directories = $optional + 112 }
    $clr = $directories + (14 * 8)
    if ($clr + 4 -gt $Bytes.Length) { return $true }
    return [System.BitConverter]::ToUInt32($Bytes, $clr) -eq 0
}

function Read-SingleFileBundle {
    # Returns the packed files of a single-file program, or $null for any other file.
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    # SHA-256 of ".net core bundle"; the eight bytes before it hold the header position.
    $hex = "8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae"
    $signature = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $signature[$i] = [System.Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $at = $latin1.GetString($bytes).IndexOf($latin1.GetString($signature), [System.StringComparison]::Ordinal)
    if ($at -lt 8) { return $null }
    $header = [System.BitConverter]::ToInt64($bytes, $at - 8)
    if ($header -le 0) { return $null }

    $stream = New-Object System.IO.MemoryStream(, $bytes)
    $reader = New-Object System.IO.BinaryReader($stream)
    $stream.Position = $header
    $major = $reader.ReadUInt32()
    [void]$reader.ReadUInt32()
    $count = $reader.ReadInt32()
    [void]$reader.ReadString()
    if ($major -ge 2) {
        for ($i = 0; $i -lt 5; $i++) { [void]$reader.ReadInt64() }
    }

    $entries = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $count; $i++) {
        $offset = $reader.ReadInt64()
        $size = $reader.ReadInt64()
        $compressed = 0
        if ($major -ge 6) { $compressed = $reader.ReadInt64() }
        $type = $reader.ReadByte()
        $entries.Add([pscustomobject]@{
                Offset = $offset; Size = $size; Compressed = $compressed; Type = $type; Path = $reader.ReadString()
            })
    }

    return [pscustomobject]@{ Bytes = $bytes; Entries = $entries }
}

function Get-BundleEntryBytes {
    param([Parameter(Mandatory = $true)]$Bundle, [Parameter(Mandatory = $true)]$Entry)

    if ($Entry.Compressed -eq 0) {
        $raw = New-Object byte[] $Entry.Size
        [System.Array]::Copy($Bundle.Bytes, $Entry.Offset, $raw, 0, $Entry.Size)
        return , $raw
    }

    $source = New-Object System.IO.MemoryStream($Bundle.Bytes, [int]$Entry.Offset, [int]$Entry.Compressed)
    $inflate = New-Object System.IO.Compression.DeflateStream($source, [System.IO.Compression.CompressionMode]::Decompress)
    $target = New-Object System.IO.MemoryStream
    $inflate.CopyTo($target)
    $inflate.Dispose()
    return , $target.ToArray()
}
