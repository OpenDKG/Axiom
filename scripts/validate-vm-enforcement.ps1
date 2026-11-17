# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Live Windows Firewall deny + rollback canary for an isolated VM.

.DESCRIPTION
    By default this prints its plan and changes nothing. With -ExecuteInIsolatedVm it creates a
    temporary outbound block rule for one program to one remote endpoint, proves the connection
    fails while the rule exists, removes the rule, and proves the connection works again.

    Loopback is deliberately not used: Windows Firewall exempts loopback traffic, so a 127.0.0.x
    canary can fail to demonstrate anything (observed on Windows 11 26100 in the Axiom lab). A
    remote endpoint is required for a real deny.

    The rule targets the running PowerShell executable by path. Use -TargetProgram to target
    another program. The rule is always removed on failure.

.PARAMETER ExecuteInIsolatedVm
    Run the live canary. Requires an elevated shell inside a disposable VM.

.PARAMETER RemoteHost
    Remote IPv4 address used for the canary (default 1.1.1.1).

.PARAMETER RemotePort
    Remote TCP port used for the canary (default 443).

.PARAMETER TargetProgram
    Program path the rule blocks (default: the current PowerShell executable).
#>
[CmdletBinding()]
param(
    [switch]$ExecuteInIsolatedVm,
    [string]$RemoteHost = "1.1.1.1",
    [int]$RemotePort = 443,
    [string]$TargetProgram = ""
)

$ErrorActionPreference = 'Stop'
$ruleName = "Axiom-VM-Validation-Canary"

if (-not $ExecuteInIsolatedVm) {
    Write-Host "[DRY-RUN] No firewall state was modified." -ForegroundColor Yellow
    Write-Host "[DRY-RUN] Live canary target: $RemoteHost`:$RemotePort (loopback is not used; Windows Firewall exempts it)"
    Write-Host "[DRY-RUN] Temporary rule name: $ruleName"
    Write-Host "[DRY-RUN] To execute the block + rollback check inside a disposable elevated VM:"
    Write-Host "          powershell -ExecutionPolicy Bypass -File .\scripts\validate-vm-enforcement.ps1 -ExecuteInIsolatedVm"
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "The live canary requires an elevated Administrator shell inside your isolated VM."
}

if ([string]::IsNullOrWhiteSpace($TargetProgram)) {
    $TargetProgram = (Get-Process -Id $PID).Path
}
if (-not (Test-Path -LiteralPath $TargetProgram)) {
    throw "Target program not found: $TargetProgram"
}
if ($RemoteHost -in @('127.0.0.1', '::1') -or $RemoteHost.StartsWith('127.')) {
    throw "Loopback targets cannot demonstrate a Windows Firewall deny. Use a remote address."
}

function Test-CanaryConnect {
    $code = @"
`$c = [System.Net.Sockets.TcpClient]::new()
try {
  `$iar = `$c.BeginConnect('$RemoteHost', $RemotePort, `$null, `$null)
  if (`$iar.AsyncWaitHandle.WaitOne(2500)) { `$c.EndConnect(`$iar); exit 0 } else { exit 1 }
} catch { exit 2 } finally { `$c.Dispose() }
"@
    $proc = Start-Process -FilePath $TargetProgram -ArgumentList @("-NoProfile", "-Command", $code) -NoNewWindow -Wait -PassThru
    return ($proc.ExitCode -eq 0)
}

$created = $false
try {
    Write-Host "[1/5] Verifying baseline connectivity to $RemoteHost`:$RemotePort..."
    if (-not (Test-CanaryConnect)) {
        throw "Baseline connection failed. The VM has no route to $RemoteHost`:$RemotePort."
    }

    Write-Host "[2/5] Creating temporary rule $ruleName (block $TargetProgram -> $RemoteHost`:$RemotePort)..."
    New-NetFirewallRule -DisplayName $ruleName -Name $ruleName `
        -Direction Outbound -Action Block -Program $TargetProgram `
        -RemoteAddress $RemoteHost -Protocol TCP -RemotePort $RemotePort -Profile Any | Out-Null
    $created = $true

    Write-Host "[3/5] Verifying the rule read-back..."
    $readback = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
    if ($readback.Action -ne 'Block' -or $readback.Enabled -ne 'True' -or $readback.Direction -ne 'Outbound') {
        throw "Rule read-back mismatch: action=$($readback.Action) enabled=$($readback.Enabled) direction=$($readback.Direction)"
    }
    Write-Host "      action=Block enabled=True direction=Outbound"

    Write-Host "[4/5] Verifying the connection is denied while the rule exists..."
    if (Test-CanaryConnect) {
        throw "The rule did not block the destination."
    }

    Write-Host "[5/5] Rolling back and verifying connectivity is restored..."
    Remove-NetFirewallRule -Name $ruleName
    $created = $false
    $remaining = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue).Count
    if ($remaining -ne 0) {
        throw "Rollback left $remaining rule(s) behind."
    }
    if (-not (Test-CanaryConnect)) {
        throw "Connectivity was not restored after rollback."
    }

    Write-Host "RESULT: OS_DENY_VERIFIED (block, read-back and rollback on $RemoteHost`:$RemotePort)"
    exit 0
}
catch {
    Write-Host "RESULT: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    if ($created) {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        Write-Host "Cleanup: removed $ruleName"
    }
}
