// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Axiom.Infrastructure.Windows.Dns;

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
    /// Ensures either the preferred adapter or the active default-route adapter points at the
    /// loopback resolver while retaining its previous non-loopback servers as fallback.
    /// Intended strictly for the elevated service host; unit tests must not invoke this on live NICs.
    /// </summary>
    public static bool EnsureAdapterPointed(string? preferredAdapterAlias, string resolverAddress = "127.0.0.1")
    {
        var adapter = SelectTargetAdapter(preferredAdapterAlias);
        if (adapter is null)
        {
            return false;
        }

        var currentIps = adapter.GetIPProperties().DnsAddresses;
        var firstV4 = currentIps.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);
        if (firstV4 is not null && IPAddress.IsLoopback(firstV4))
        {
            return false;
        }

        var currentStrings = currentIps.Select(address => address.ToString()).ToArray();
        var savedStrings = DnsAdapterSnapshot.TryReadServerAddresses(BackupPath, adapter.Name, out var saved)
            ? saved.ToArray()
            : currentStrings;
        var previous = savedStrings.Length > 0 ? savedStrings : currentStrings;

        var ipv4Plan = DnsAdapterPlan.Build(
            resolverAddress,
            previous.Where(text => IPAddress.TryParse(text, out var addr) && !addr.IsIPv6SiteLocal));
        if (!DnsAdapterPlan.HasFallback(ipv4Plan))
        {
            return false;
        }

        var ipv6Plan = DnsAdapterPlan.Build(
            IPAddress.IPv6Loopback.ToString(),
            previous.Where(text => IPAddress.TryParse(text, out var addr) && !addr.IsIPv6SiteLocal));

        var aliasLiteral = EscapePowerShellSingleQuoted(adapter.Name);
        var backupLiteral = EscapePowerShellSingleQuoted(BackupPath);
        var setV4 = $"Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @('" +
                    string.Join("','", ipv4Plan.Select(EscapePowerShellSingleQuoted)) + "')";
        var setV6 = DnsAdapterPlan.HasFallback(ipv6Plan)
            ? "Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @('" +
              string.Join("','", ipv6Plan.Select(EscapePowerShellSingleQuoted)) + "')"
            : string.Empty;

        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $backup = '{{backupLiteral}}'
            $alias = '{{aliasLiteral}}'
            if (-not (Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue)) { exit 0 }
            $directory = Split-Path -Parent $backup
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
            if (-not (Test-Path -LiteralPath $backup)) {
              $entries = @(Get-DnsClientServerAddress | Where-Object { $_.AddressFamily -in 2,23 } | ForEach-Object {
                [pscustomobject]@{
                  interfaceAlias = $_.InterfaceAlias
                  interfaceIndex = $_.InterfaceIndex
                  addressFamily = [int]$_.AddressFamily
                  serverAddresses = @($_.ServerAddresses)
                }
              })
              [pscustomobject]@{
                capturedUtc = [DateTimeOffset]::UtcNow.ToString('O')
                machine = $env:COMPUTERNAME
                interfaces = $entries
              } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $backup -Encoding UTF8
            }
            {{setV4}}
            {{setV6}}
            ipconfig /flushdns | Out-Null
            Write-Host "Privacy Shield DNS automatically pointed '$alias' at the loopback resolver."
            """;

        return RunHiddenPowerShell(script);
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

        return RunHiddenPowerShell(script);
    }

    private static NetworkInterface? SelectTargetAdapter(string? preferredAdapterAlias)
    {
        try
        {
            var candidates = NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
                                  adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                  adapter.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .ToArray();

            if (!string.IsNullOrWhiteSpace(preferredAdapterAlias))
            {
                var preferred = candidates.FirstOrDefault(adapter =>
                    string.Equals(adapter.Name, preferredAdapterAlias.Trim(), StringComparison.OrdinalIgnoreCase));
                if (preferred is not null)
                {
                    return preferred;
                }
            }

            return candidates.FirstOrDefault(adapter =>
                adapter.GetIPProperties().GatewayAddresses.Any(gw =>
                    gw.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.Any.Equals(gw.Address)));
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    private static string EscapePowerShellSingleQuoted(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static bool RunHiddenPowerShell(string script)
    {
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
            return process.ExitCode == 0;
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return false;
        }
    }
}
