// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;

namespace Axiom.Service;

/// <summary>
/// Failsafe for the adapter DNS change the Privacy Shield helper makes. If the resolver is not
/// running (disabled, stopped or failed) while an adapter still points at 127.0.0.1, every name
/// lookup on that adapter dies. The service therefore restores the saved DNS, or resets the adapter
/// to DHCP when no backup is available, so stopping Axiom or the service always returns the machine
/// to a working network. The service runs as LocalSystem and needs no elevation prompt.
/// </summary>
public static class PrivacyDnsFailSafe
{
    private static readonly string BackupPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Axiom",
        "privacy-shield-dns-backup.json");

    /// <summary>True when any non-loopback adapter still sends DNS to the loopback resolver.</summary>
    public static bool AnyAdapterUsesLoopbackDns()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
                                  adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Any(adapter => adapter.GetIPProperties().DnsAddresses.Any(System.Net.IPAddress.IsLoopback));
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Restores saved DNS for adapters that point at the loopback resolver right now. Only touched
    /// adapters change, and only when the resolver is not running. Returns true when something was
    /// changed or attempted.
    /// </summary>
    public static bool RestoreIfNeeded()
    {
        if (!AnyAdapterUsesLoopbackDns())
        {
            return false;
        }

        var backup = BackupPath.Replace("'", "''", StringComparison.Ordinal);
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $backup = '{{backup}}'
            $targets = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
              Where-Object { @($_.ServerAddresses) -contains '127.0.0.1' })
            if ($targets.Count -eq 0) { exit 0 }
            $usable = $false
            if (Test-Path -LiteralPath $backup) {
              $item = Get-Item -LiteralPath $backup -Force
              $ownerSid = (New-Object System.Security.Principal.NTAccount((Get-Acl -LiteralPath $backup).Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
              if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                  $ownerSid -in @('S-1-5-18', 'S-1-5-32-544')) {
                $snapshot = Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
                $valid = $true
                foreach ($entry in @($snapshot.interfaces)) {
                  foreach ($address in @($entry.serverAddresses)) {
                    $parsed = $null
                    if (-not [System.Net.IPAddress]::TryParse([string]$address, [ref]$parsed)) { $valid = $false }
                  }
                }
                if ($valid) {
                  $usable = $true
                  $covered = @()
                  foreach ($entry in @($snapshot.interfaces)) {
                    if ($targets.InterfaceAlias -contains $entry.interfaceAlias) {
                      $covered += [string]$entry.interfaceAlias
                      if (@($entry.serverAddresses).Count -eq 0) {
                        Set-DnsClientServerAddress -InterfaceAlias $entry.interfaceAlias -ResetServerAddresses
                      } else {
                        Set-DnsClientServerAddress -InterfaceAlias $entry.interfaceAlias -ServerAddresses @($entry.serverAddresses)
                      }
                    }
                  }
                  foreach ($target in $targets) {
                    if ($covered -notcontains [string]$target.InterfaceAlias) {
                      Set-DnsClientServerAddress -InterfaceAlias $target.InterfaceAlias -ResetServerAddresses
                    }
                  }
                }
              }
            }
            if (-not $usable) {
              # No trustworthy snapshot: fall back to DHCP instead of applying attacker input.
              foreach ($target in $targets) {
                Set-DnsClientServerAddress -InterfaceAlias $target.InterfaceAlias -ResetServerAddresses
              }
            }
            ipconfig /flushdns | Out-Null
            Write-Host "Privacy Shield DNS failsafe processed $($targets.Count) adapter(s)."
            """;

        try
        {
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            using var process = Process.Start(new ProcessStartInfo(
                "powershell.exe",
                $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (process is null)
            {
                return false;
            }

            process.WaitForExit(20_000);
            return true;
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return false;
        }
    }
}
