// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Axiom.Infrastructure.Windows.Dns;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>
/// Explicit UAC-gated adapter DNS helper. Axiom never elevates itself or changes DNS silently;
/// the user confirms the Windows elevation prompt for each action. The adapter keeps its previous
/// DNS servers behind the resolver, so a stopped or hung resolver cannot take the network down.
/// </summary>
internal static class PrivacyShieldDnsHelper
{
    public static string BackupPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "privacy-shield-dns-backup.json");

    public static async Task<int> EnableAsync(
        string interfaceAlias,
        string resolverAddress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceAlias);
        ArgumentException.ThrowIfNullOrWhiteSpace(resolverAddress);

        var alias = Escape(interfaceAlias);
        var backup = Escape(BackupPath);
        var planner = BuildAddressPlan(interfaceAlias, resolverAddress);
        var setV4 = BuildSetLine(planner.IPv4);
        var setV6 = BuildSetLine(planner.IPv6);

        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $backup = '{{backup}}'
            $alias = '{{alias}}'
            if (-not (Test-Path -LiteralPath $backup)) {
              $directory = Split-Path -Parent $backup
              New-Item -ItemType Directory -Force -Path $directory | Out-Null
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
            # Keep a machine-wide copy the Axiom service (LocalSystem) can read for its failsafe.
            $machine = Join-Path $env:ProgramData 'Axiom\privacy-shield-dns-backup.json'
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $machine) | Out-Null
            Copy-Item -LiteralPath $backup -Destination $machine -Force
            {{setV4}}{{setV6}}
            Write-Host "DNS for '$alias' now points at the Privacy Shield loopback resolver."
            """;

        return await RunElevatedAsync(script, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<int> RestoreAsync(CancellationToken cancellationToken)
    {
        var backup = Escape(BackupPath);
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            $backup = '{{backup}}'
            if (-not (Test-Path -LiteralPath $backup)) {
              throw 'No Privacy Shield DNS backup exists.'
            }
            $snapshot = Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
            foreach ($entry in @($snapshot.interfaces)) {
              if (@($entry.serverAddresses).Count -eq 0) {
                Set-DnsClientServerAddress -InterfaceAlias $entry.interfaceAlias -ResetServerAddresses
              } else {
                Set-DnsClientServerAddress -InterfaceAlias $entry.interfaceAlias -ServerAddresses @($entry.serverAddresses)
              }
            }
            Write-Host 'Original adapter DNS settings restored.'
            """;

        return await RunElevatedAsync(script, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Resolver first, the adapter's earlier servers behind it. Only a family that has a real
    /// fallback is changed, so the helper never creates a single-server adapter.
    /// </summary>
    internal static (IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6) BuildAddressPlan(
        string interfaceAlias,
        string resolverAddress)
    {
        if (!IPAddress.TryParse(resolverAddress, out var resolver))
        {
            throw new ArgumentException("The resolver address is not a valid IP address.", nameof(resolverAddress));
        }

        var previous = ReadSavedServers(interfaceAlias) ?? ReadCurrentServers(interfaceAlias);
        var ipv4 = resolver.AddressFamily == AddressFamily.InterNetwork
            ? DnsAdapterPlan.Build(resolver.ToString(), previous)
            : [];
        var ipv6 = resolver.AddressFamily == AddressFamily.InterNetworkV6
            ? DnsAdapterPlan.Build(resolver.ToString(), previous)
            : DnsAdapterPlan.Build(IPAddress.IPv6Loopback.ToString(), previous);

        return (
            DnsAdapterPlan.HasFallback(ipv4) ? ipv4 : Array.Empty<string>(),
            DnsAdapterPlan.HasFallback(ipv6) ? ipv6 : Array.Empty<string>());
    }

    private static string BuildSetLine(IReadOnlyList<string> servers) =>
        servers.Count < 2
            ? string.Empty
            : $"Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @('" +
              string.Join("','", servers.Select(Escape)) + "')\r\n";

    private static string[]? ReadSavedServers(string interfaceAlias) =>
        DnsAdapterSnapshot.TryReadServerAddresses(BackupPath, interfaceAlias, out var addresses)
            ? addresses.ToArray()
            : null;
    private static string[] ReadCurrentServers(string interfaceAlias)
    {
        try
        {
            var network = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(candidate => string.Equals(candidate.Name, interfaceAlias, StringComparison.OrdinalIgnoreCase));
            return network?
                .GetIPProperties()
                .DnsAddresses
                .Select(address => address.ToString())
                .ToArray() ?? [];
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    private static async Task<int> RunElevatedAsync(string script, CancellationToken cancellationToken)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The elevated DNS helper could not start.");
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return process.ExitCode;
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
