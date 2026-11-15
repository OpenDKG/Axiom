# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    Safe validation harness for Axiom Phases 4 & 5.
    By default runs in non-mutating -DryRun mode (reads configuration & prints commands only).
    Pass -ExecuteInIsolatedVm inside an elevated disposable Windows VM to run live Windows Firewall
    dual-destination canary + rollback checks without touching arbitrary production rules.
#>
[CmdletBinding()]
param(
    [switch]$ExecuteInIsolatedVm,
    [int]$BlockedPort = 59441,
    [int]$ControlPort = 59442
)

$ErrorActionPreference = 'Stop'
$ruleName = "Axiom-VM-Validation-Canary"

if (-not $ExecuteInIsolatedVm) {
    Write-Host "[DRY-RUN] No firewall or DNS state was modified." -ForegroundColor Yellow
    Write-Host "[DRY-RUN] Phase 4 readiness check: NetSecurity cmdlets available: $((Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) -ne $null)"
    Write-Host "[DRY-RUN] Phase 4 target rule name (when -ExecuteInIsolatedVm is supplied): $ruleName"
    Write-Host "[DRY-RUN] To execute live canary + rollback verification inside a disposable elevated VM:"
    Write-Host "          powershell -ExecutionPolicy Bypass -File .\scripts\validate-vm-enforcement.ps1 -ExecuteInIsolatedVm"
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Live Phase 4 Windows Firewall canary requires an elevated Administrator shell inside your isolated VM."
}

$blockedIpV4 = "127.0.0.2"
$controlIpV4 = "127.0.0.3"
$tempRoot = Join-Path $env:TEMP ("axiom-fw-canary-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
$powershellCopy = Join-Path $tempRoot "pwsh-canary.exe"
$sourceExe = (Get-Process -Id $PID).Path
Copy-Item -Path $sourceExe -Destination $powershellCopy -Force

$listenerBlocked = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($blockedIpV4), $BlockedPort)
$listenerControl = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($controlIpV4), $ControlPort)

function Test-CanaryConnect([string]$ExePath, [string]$Ip, [int]$Port) {
    $code = @"
\$c = [System.Net.Sockets.TcpClient]::new()
try {
  \$iar = \$c.BeginConnect('$Ip', $Port, \$null, \$null)
  if (\$iar.AsyncWaitHandle.WaitOne(1500)) { \$c.EndConnect(\$iar); exit 0 } else { exit 1 }
} catch { exit 2 } finally { \$c.Dispose() }
"@
    $proc = Start-Process -FilePath $ExePath -ArgumentList @("-NoProfile", "-Command", $code) -NoNewWindow -Wait -PassThru
    return ($proc.ExitCode -eq 0)
}

try {
    $listenerBlocked.Start()
    $listenerControl.Start()

    Write-Host "[1/5] Verifying baseline connectivity before rule creation..."
    $preBlocked = Test-CanaryConnect -ExePath $powershellCopy -Ip $blockedIpV4 -Port $BlockedPort
    $preControl = Test-CanaryConnect -ExePath $powershellCopy -Ip $controlIpV4 -Port $ControlPort
    if (-not $preBlocked -or -not $preControl) {
        throw "Baseline pre-check failed: blocked=$preBlocked control=$preControl"
    }

    Write-Host "[2/5] Creating temporary Axiom validation rule ($ruleName)..."
    New-NetFirewallRule -DisplayName $ruleName `
        -Name $ruleName `
        -Direction Outbound `
        -Action Block `
        -Program $powershellCopy `
        -RemoteAddress $blockedIpV4 `
        -Protocol TCP `
        -RemotePort $BlockedPort `
        -Profile Any | Out-Null

    Write-Host "[3/5] Verifying rule read-back matches expected scope..."
    $readback = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
    if ($readback.Enabled -ne 'True' -or $readback.Action -ne 'Block') {
        throw "Rule read-back verification failed."
    }

    Write-Host "[4/5] Running dual-destination probe..."
    $postBlocked = Test-CanaryConnect -ExePath $powershellCopy -Ip $blockedIpV4 -Port $BlockedPort
    $postControl = Test-CanaryConnect -ExePath $powershellCopy -Ip $controlIpV4 -Port $ControlPort
    if ($postBlocked) {
        throw "OS_DENY_FAILED: blocked endpoint $blockedIpV4`:$BlockedPort succeeded under active rule!"
    }
    if (-not $postControl) {
        throw "CONTROL_FAILED: allowed control endpoint $controlIpV4`:$ControlPort failed!"
    }

    Write-Host "[5/5] Removing rule and verifying network recovery..."
    Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
    $recovered = Test-CanaryConnect -ExePath $powershellCopy -Ip $blockedIpV4 -Port $BlockedPort
    if (-not $recovered) {
        throw "RECOVERY_FAILED: blocked endpoint did not recover after rule removal."
    }

    Write-Host "PASS [OS_DENY_VERIFIED + ROLLBACK]: Read-back OK, blocked=$blockedIpV4`:$BlockedPort denied, control=$controlIpV4`:$ControlPort succeeded, recovery verified." -ForegroundColor Green
}
finally {
    Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    try { $listenerBlocked.Stop() } catch {}
    try { $listenerControl.Stop() } catch {}
    Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
