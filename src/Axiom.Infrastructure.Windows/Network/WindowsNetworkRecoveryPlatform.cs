// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using Axiom.Presentation;

namespace Axiom.Infrastructure.Windows.Network;

/// <summary>
/// Windows capture/restore built on the built-in DNS and firewall cmdlets. Reads are side-effect
/// free; writes happen only during an explicit restore and are limited to Axiom-prefixed rules.
/// </summary>
public sealed class WindowsNetworkRecoveryPlatform : INetworkRecoveryPlatform
{
    private const string AxiomRulePrefix = "Axiom::";

    public IReadOnlyList<NetworkAdapterDns> CaptureAdapters()
    {
        var output = Run(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | " +
            "ForEach-Object { \"$($_.InterfaceGuid)|$($_.InterfaceAlias)|$($_.ServerAddresses -join ';')\" }");

        var adapters = new List<NetworkAdapterDns>();
        foreach (var line in Lines(output))
        {
            var parts = line.Split('|');
            if (parts.Length != 3 || string.IsNullOrWhiteSpace(parts[0]))
            {
                continue;
            }

            adapters.Add(new NetworkAdapterDns(
                parts[0],
                parts[1],
                UsesDhcp: false,
                parts[2].Split(';', StringSplitOptions.RemoveEmptyEntries)));
        }

        return adapters;
    }

    public IReadOnlyList<string> CaptureAxiomRules()
    {
        var output = Run(
            "Get-NetFirewallRule -DisplayName 'Axiom::*' -ErrorAction SilentlyContinue | " +
            "Select-Object -ExpandProperty DisplayName");

        return Lines(output)
            .Where(line => line.StartsWith(AxiomRulePrefix, StringComparison.Ordinal))
            .ToArray();
    }

    public void ApplyAdapterDns(NetworkAdapterDns adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        if (!Guid.TryParse(adapter.AdapterId, out _))
        {
            throw new InvalidOperationException("the saved adapter identifier is not a GUID");
        }

        if (adapter.Servers.Count == 0)
        {
            Run($"Set-DnsClientServerAddress -InterfaceGuid '{adapter.AdapterId}' -ResetServerAddresses");
            return;
        }

        var servers = string.Join(',', adapter.Servers.Select(server => "'" + Escape(server) + "'"));
        Run($"Set-DnsClientServerAddress -InterfaceGuid '{adapter.AdapterId}' -ServerAddresses {servers}");
    }

    public void RemoveAxiomRule(string displayName)
    {
        ArgumentNullException.ThrowIfNull(displayName);

        if (!displayName.StartsWith(AxiomRulePrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("refusing to remove a rule Axiom does not own");
        }

        Run($"Remove-NetFirewallRule -DisplayName '{Escape(displayName)}' -ErrorAction Stop");
    }

    private static string[] Lines(string output) =>
        output.Replace("\r", string.Empty, StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static string Run(string command)
    {
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(command);

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("PowerShell could not be started");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();

        if (!process.WaitForExit(15000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            throw new InvalidOperationException("the network command timed out");
        }

        if (process.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? $"exit code {process.ExitCode}" : stderr.Trim();
            throw new InvalidOperationException(detail);
        }

        return stdout;
    }
}
