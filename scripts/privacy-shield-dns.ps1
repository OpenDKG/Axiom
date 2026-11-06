# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Explicitly save, enable or restore Windows DNS settings for Privacy Shield.

.DESCRIPTION
    This is a manual, administrator-only helper. It is never called by Axiom automatically.
    Save first, enable only after the Axiom Privacy Shield resolver is listening on port 53,
    and restore immediately if resolution fails. The saved file contains interface aliases and
    DNS addresses, not query history.

.EXAMPLE
    .\scripts\privacy-shield-dns.ps1 -Action Save

.EXAMPLE
    .\scripts\privacy-shield-dns.ps1 -Action Enable -InterfaceAlias "Ethernet"

.EXAMPLE
    .\scripts\privacy-shield-dns.ps1 -Action Restore
#>
param(
    [ValidateSet("Save", "Enable", "Restore")]
    [string]$Action = "Save",
    [string]$InterfaceAlias = "",
    [string]$BackupPath = ""
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Privacy Shield DNS changes require an elevated PowerShell window."
}

if (-not $BackupPath) {
    $BackupPath = Join-Path $env:LOCALAPPDATA "Netpetra\privacy-shield-dns-backup.json"
}

function Get-DnsSnapshot {
    Get-DnsClientServerAddress |
        Where-Object { $_.AddressFamily -in 2, 23 } |
        ForEach-Object {
            [pscustomobject]@{
                interfaceAlias = $_.InterfaceAlias
                interfaceIndex = $_.InterfaceIndex
                addressFamily = [int]$_.AddressFamily
                serverAddresses = @($_.ServerAddresses)
            }
        }
}

switch ($Action) {
    "Save" {
        $directory = Split-Path -Parent $BackupPath
        if ($directory) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }

        [pscustomobject]@{
            capturedUtc = [DateTimeOffset]::UtcNow.ToString("O")
            machine = $env:COMPUTERNAME
            interfaces = @(Get-DnsSnapshot)
        } | ConvertTo-Json -Depth 6 | Set-Content $BackupPath -Encoding UTF8
        Write-Host "Saved DNS settings to $BackupPath" -ForegroundColor Green
        break
    }

    "Enable" {
        if (-not (Test-Path $BackupPath)) {
            throw "No DNS backup exists at $BackupPath. Run -Action Save first."
        }

        if (-not $InterfaceAlias) {
            throw "Pass -InterfaceAlias explicitly. This script does not change every adapter by default."
        }

        Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses @("127.0.0.1")
        try {
            Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses @("::1")
        }
        catch {
            Write-Warning "IPv6 loopback DNS could not be set for '$InterfaceAlias': $($_.Exception.Message)"
        }

        Write-Host "Set '$InterfaceAlias' DNS to the Privacy Shield loopback resolver." -ForegroundColor Yellow
        Write-Host "Restore with: $PSCommandPath -Action Restore -BackupPath '$BackupPath'" -ForegroundColor Yellow
        break
    }

    "Restore" {
        if (-not (Test-Path $BackupPath)) {
            throw "DNS backup not found: $BackupPath"
        }

        $snapshot = Get-Content $BackupPath -Raw | ConvertFrom-Json
        foreach ($entry in @($snapshot.interfaces)) {
            try {
                if (@($entry.serverAddresses).Count -eq 0) {
                    Set-DnsClientServerAddress -InterfaceAlias $entry.interfaceAlias -ResetServerAddresses
                }
                else {
                    Set-DnsClientServerAddress `
                        -InterfaceAlias $entry.interfaceAlias `
                        -ServerAddresses @($entry.serverAddresses)
                }
                Write-Host "Restored $($entry.interfaceAlias) ($($entry.addressFamily))" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not restore '$($entry.interfaceAlias)': $($_.Exception.Message)"
            }
        }
        break
    }
}
