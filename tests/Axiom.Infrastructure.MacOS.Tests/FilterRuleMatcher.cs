// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;

using Axiom.Infrastructure.MacOS.Filter;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>Flow facts a rule is evaluated against.</summary>
public sealed record FilterFlowFacts(
    string AppPath,
    string Direction,
    string Protocol,
    IPAddress? RemoteAddress,
    int RemotePort);

/// <summary>Verdict of the reference evaluation.</summary>
public sealed record FilterVerdict(string Action, FilterRule? Rule);

/// <summary>
/// Test-only reference implementation of the rule semantics in docs/MACOS_ARCHITECTURE.md
/// section 3.1 (review #18: nothing in src uses it; the AxiomFilter extension implements the same
/// rules in Swift). Both sides are checked against macos/Tests/fixtures/rules-cases.json so the
/// contract cannot drift silently. Windows Firewall semantics: an enabled matching block rule wins
/// over any allow rule; without a match traffic is allowed.
/// </summary>
internal static class FilterRuleMatcher
{
    public static FilterVerdict Evaluate(FilterRuleTable table, FilterFlowFacts flow)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(flow);

        FilterRule? allow = null;
        foreach (var rule in table.Rules)
        {
            if (!Matches(rule, flow))
            {
                continue;
            }

            if (string.Equals(rule.Action, FilterRuleTable.ActionBlock, StringComparison.Ordinal))
            {
                return new FilterVerdict(FilterRuleTable.ActionBlock, rule);
            }

            allow ??= rule;
        }

        return new FilterVerdict(FilterRuleTable.ActionAllow, allow);
    }

    public static bool Matches(FilterRule rule, FilterFlowFacts flow)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(flow);

        return rule.Enabled &&
               string.Equals(rule.Direction, flow.Direction, StringComparison.Ordinal) &&
               AppMatches(rule.AppPath, flow.AppPath) &&
               ProtocolMatches(rule.Protocol, flow.Protocol) &&
               AddressMatches(rule.RemoteAddresses, flow.RemoteAddress) &&
               PortMatches(rule.RemotePorts, flow.RemotePort);
    }

    /// <summary>Exact executable path, or any executable inside a directory/bundle path.</summary>
    public static bool AppMatches(string? rulePath, string? flowPath)
    {
        if (string.IsNullOrWhiteSpace(rulePath) || rulePath.Trim() == "*")
        {
            return true;
        }

        if (string.IsNullOrEmpty(flowPath))
        {
            return false;
        }

        // "/Applications/Foo.app/" (directory form) still matches the bundle path itself.
        var normalized = rulePath.Trim().TrimEnd('/');
        if (normalized.Length == 0 || string.Equals(normalized, flowPath, StringComparison.Ordinal))
        {
            return true;
        }

        return flowPath.StartsWith(normalized + "/", StringComparison.Ordinal);
    }

    /// <summary><c>icmp</c> rules are carried in the table but are not filtered yet.</summary>
    public static bool ProtocolMatches(string? ruleProtocol, string? flowProtocol) =>
        (ruleProtocol ?? FilterRuleTable.ProtocolAny) switch
        {
            FilterRuleTable.ProtocolAny => true,
            FilterRuleTable.ProtocolTcp or FilterRuleTable.ProtocolUdp =>
                string.Equals(ruleProtocol, flowProtocol, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };

    public static bool AddressMatches(IReadOnlyList<string>? ruleAddresses, IPAddress? remote)
    {
        if (ruleAddresses is null || ruleAddresses.Count == 0)
        {
            return true;
        }

        foreach (var entry in ruleAddresses)
        {
            var value = entry.Trim();
            if (value == "*")
            {
                return true;
            }

            if (remote is not null && AddressInEntry(remote, value))
            {
                return true;
            }
        }

        return false;
    }

    public static bool PortMatches(string? rulePorts, int remotePort)
    {
        if (string.IsNullOrWhiteSpace(rulePorts))
        {
            return true;
        }

        foreach (var part in rulePorts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part == "*")
            {
                return true;
            }

            var dash = part.IndexOf('-', StringComparison.Ordinal);
            if (dash > 0)
            {
                if (int.TryParse(part[..dash], NumberStyles.None, CultureInfo.InvariantCulture, out var low) &&
                    int.TryParse(part[(dash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var high) &&
                    remotePort >= low && remotePort <= high)
                {
                    return true;
                }

                continue;
            }

            if (int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port == remotePort)
            {
                return true;
            }
        }

        return false;
    }

    private static bool AddressInEntry(IPAddress remote, string entry)
    {
        if (remote.IsIPv4MappedToIPv6)
        {
            remote = remote.MapToIPv4();
        }

        var slash = entry.IndexOf('/', StringComparison.Ordinal);
        if (slash < 0)
        {
            var dash = entry.IndexOf('-', StringComparison.Ordinal);
            if (dash > 0)
            {
                return RangeContains(entry[..dash], entry[(dash + 1)..], remote);
            }

            return IPAddress.TryParse(entry, out var single) &&
                   (single.IsIPv4MappedToIPv6 ? single.MapToIPv4() : single).Equals(remote);
        }

        if (!IPAddress.TryParse(entry[..slash], out var network) ||
            !int.TryParse(entry[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefixLength))
        {
            return false;
        }

        if (network.IsIPv4MappedToIPv6)
        {
            // "::ffff:10.0.0.0/104" is the v4 network 10.0.0.0/8.
            network = network.MapToIPv4();
            prefixLength -= 96;
        }

        if (network.AddressFamily != remote.AddressFamily)
        {
            return false;
        }

        var maxBits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > maxBits)
        {
            return false;
        }

        var networkBytes = network.GetAddressBytes();
        var remoteBytes = remote.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        for (var index = 0; index < fullBytes; index++)
        {
            if (networkBytes[index] != remoteBytes[index])
            {
                return false;
            }
        }

        var remainingBits = prefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (networkBytes[fullBytes] & mask) == (remoteBytes[fullBytes] & mask);
    }

    /// <summary>Inclusive "low-high" range of the same family; a reversed range matches nothing.</summary>
    private static bool RangeContains(string lowText, string highText, IPAddress remote)
    {
        if (!IPAddress.TryParse(lowText.Trim(), out var low) || !IPAddress.TryParse(highText.Trim(), out var high))
        {
            return false;
        }

        low = low.IsIPv4MappedToIPv6 ? low.MapToIPv4() : low;
        high = high.IsIPv4MappedToIPv6 ? high.MapToIPv4() : high;
        if (low.AddressFamily != remote.AddressFamily || high.AddressFamily != remote.AddressFamily)
        {
            return false;
        }

        var lowBytes = low.GetAddressBytes();
        var highBytes = high.GetAddressBytes();
        var remoteBytes = remote.GetAddressBytes();
        return lowBytes.AsSpan().SequenceCompareTo(highBytes) <= 0 &&
               lowBytes.AsSpan().SequenceCompareTo(remoteBytes) <= 0 &&
               remoteBytes.AsSpan().SequenceCompareTo(highBytes) <= 0;
    }
}
