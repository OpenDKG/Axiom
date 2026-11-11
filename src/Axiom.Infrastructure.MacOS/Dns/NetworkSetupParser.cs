// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;

namespace Axiom.Infrastructure.MacOS.Dns;

/// <summary>A network service from <c>networksetup -listallnetworkservices</c>.</summary>
public sealed record NetworkServiceEntry(string Name, bool Enabled);

/// <summary>A service and its BSD device from <c>networksetup -listnetworkserviceorder</c>.</summary>
public sealed record NetworkServiceDevice(string Name, string Device);

/// <summary>Parsers for <c>networksetup</c> and <c>scutil --dns</c> output.</summary>
public static class NetworkSetupParser
{
    /// <summary>Services in order; a leading <c>*</c> marks a disabled service.</summary>
    public static IReadOnlyList<NetworkServiceEntry> ParseServices(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        var result = new List<NetworkServiceEntry>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line) ||
                line.StartsWith("An asterisk (*)", StringComparison.Ordinal) ||
                line.StartsWith("**", StringComparison.Ordinal))
            {
                continue;
            }

            var disabled = line.StartsWith('*');
            var name = (disabled ? line[1..] : line).Trim();
            if (name.Length > 0)
            {
                result.Add(new NetworkServiceEntry(name, !disabled));
            }
        }

        return result;
    }

    /// <summary>
    /// Service -> device pairs from <c>-listnetworkserviceorder</c>, e.g. <c>(1) Wi-Fi</c> followed by
    /// <c>(Hardware Port: Wi-Fi, Device: en0)</c>. Services without a device line are omitted.
    /// </summary>
    public static IReadOnlyList<NetworkServiceDevice> ParseServiceOrder(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        var result = new List<NetworkServiceDevice>();
        string? pending = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith('(') && !line.StartsWith("(Hardware Port:", StringComparison.Ordinal))
            {
                // "(1) Wi-Fi" or "(*) Bluetooth PAN" (disabled).
                var close = line.IndexOf(')', StringComparison.Ordinal);
                pending = close > 0 ? line[(close + 1)..].Trim() : null;
                continue;
            }

            if (pending is not null && line.StartsWith("(Hardware Port:", StringComparison.Ordinal))
            {
                var marker = line.IndexOf("Device:", StringComparison.Ordinal);
                if (marker >= 0)
                {
                    var device = line[(marker + "Device:".Length)..].TrimEnd(')').Trim();
                    if (device.Length > 0)
                    {
                        result.Add(new NetworkServiceDevice(pending, device));
                    }
                }

                pending = null;
            }
        }

        return result;
    }

    /// <summary>
    /// Whether <c>ifconfig &lt;device&gt;</c> reports an active link. Null when the output has no
    /// <c>status:</c> line (the interface kind does not report one), so the caller can be conservative.
    /// </summary>
    public static bool? ParseInterfaceActive(string ifconfigOutput)
    {
        ArgumentNullException.ThrowIfNull(ifconfigOutput);

        foreach (var raw in ifconfigOutput.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("status:", StringComparison.Ordinal))
            {
                return string.Equals(line["status:".Length..].Trim(), "active", StringComparison.Ordinal);
            }
        }

        return null;
    }

    /// <summary>
    /// DNS servers of one service; empty when none are set manually ("There aren't any DNS Servers
    /// set on ..."), which means the service uses DHCP/automatic DNS. Null when the output is an
    /// error (unknown service).
    /// </summary>
    public static IReadOnlyList<string>? ParseDnsServers(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        if (output.Contains("aren't any DNS Servers", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("are not any DNS Servers", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        if (output.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("not a recognized network service", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var servers = new List<string>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (IPAddress.TryParse(line, out _))
            {
                servers.Add(line);
            }
        }

        return servers;
    }

    /// <summary>
    /// Nameservers of the default (unscoped, domain-less) resolvers in <c>scutil --dns</c>, in
    /// order, followed by scoped resolvers; duplicates removed.
    /// </summary>
    public static IReadOnlyList<IPAddress> ParseScutilNameservers(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        var result = new List<IPAddress>();
        var current = new List<IPAddress>();
        var currentHasDomain = false;

        void Flush()
        {
            if (!currentHasDomain)
            {
                foreach (var address in current.Where(address => !result.Contains(address)))
                {
                    result.Add(address);
                }
            }

            current.Clear();
            currentHasDomain = false;
        }

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("resolver #", StringComparison.Ordinal) ||
                line.StartsWith("DNS configuration", StringComparison.Ordinal))
            {
                Flush();
                continue;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                continue;
            }

            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (key.StartsWith("nameserver[", StringComparison.Ordinal) && IPAddress.TryParse(value, out var address))
            {
                current.Add(address);
            }
            else if (string.Equals(key, "domain", StringComparison.Ordinal))
            {
                currentHasDomain = true;
            }
        }

        Flush();
        return result;
    }
}
