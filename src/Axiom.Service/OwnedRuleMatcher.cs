// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Monitoring;

namespace Axiom.Service;

/// <summary>
/// Matches an observed flow against the firewall rules Axiom owns. It deliberately reports only
/// what Axiom can prove: an owned allow/block rule, or that no owned rule matches. Windows default
/// policy and third-party rules remain outside this evaluation.
/// </summary>
public static class OwnedRuleMatcher
{
    public static ConnectionRuleStatus Evaluate(
        IReadOnlyList<ManagedRule> rules,
        LiveConnection connection)
    {
        var allow = false;
        var block = false;

        foreach (var rule in rules)
        {
            if (!rule.Spec.Enabled || rule.State != RuleState.Applied)
            {
                continue;
            }

            if (!Matches(rule.Spec, connection))
            {
                continue;
            }

            if (rule.Spec.Action == FirewallAction.Block)
            {
                block = true;
            }
            else
            {
                allow = true;
            }
        }

        return block
            ? ConnectionRuleStatus.BlockedByOwnedRule
            : allow
                ? ConnectionRuleStatus.AllowedByOwnedRule
                : ConnectionRuleStatus.NoOwnedRule;
    }

    private static bool Matches(RuleSpec rule, LiveConnection connection)
    {
        if (string.IsNullOrWhiteSpace(rule.AppPath) ||
            string.IsNullOrWhiteSpace(connection.AppPath))
        {
            return false;
        }

        if (!string.Equals(
                rule.AppPath.Trim(),
                connection.AppPath.Trim(),
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var ruleDirection = rule.Direction == FirewallDirection.Outbound
            ? ConnectionDirection.Outbound
            : ConnectionDirection.Inbound;
        if (connection.Direction != ruleDirection)
        {
            return false;
        }

        if (rule.Protocol != NetworkProtocol.Any &&
            rule.Protocol.ToString() != connection.Protocol.ToString())
        {
            return false;
        }

        if (!MatchesPort(rule.RemotePorts, connection.RemoteEndpoint))
        {
            return false;
        }

        return MatchesAddress(rule.RemoteAddresses, connection.RemoteEndpoint);
    }

    private static bool MatchesPort(string? ports, string remoteEndpoint)
    {
        if (string.IsNullOrWhiteSpace(ports))
        {
            return true;
        }

        if (!TryGetRemotePort(remoteEndpoint, out var port))
        {
            return false;
        }

        foreach (var part in ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var range = part.Split('-', StringSplitOptions.TrimEntries);
            if (range.Length == 1 &&
                int.TryParse(range[0], out var single) &&
                single == port)
            {
                return true;
            }

            if (range.Length == 2 &&
                int.TryParse(range[0], out var from) &&
                int.TryParse(range[1], out var to) &&
                port >= from && port <= to)
            {
                return true;
            }
        }

        return false;
    }

    private static bool MatchesAddress(IReadOnlyList<string> addresses, string remoteEndpoint)
    {
        if (addresses.Count == 0)
        {
            return true;
        }

        if (!TryGetRemoteAddress(remoteEndpoint, out var remote))
        {
            return false;
        }

        foreach (var address in addresses)
        {
            if (string.IsNullOrWhiteSpace(address) ||
                address is "*" or "any" ||
                string.Equals(address, "Any", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (TryParseCidr(address, out var network, out var prefix) &&
                IsInNetwork(remote, network, prefix))
            {
                return true;
            }

            if (IPAddress.TryParse(address, out var single) && single.Equals(remote))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryParseCidr(string value, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        var slash = value.IndexOf('/');
        if (slash <= 0)
        {
            return false;
        }

        if (!IPAddress.TryParse(value[..slash], out var parsedNetwork) ||
            !int.TryParse(value[(slash + 1)..], out prefix) ||
            prefix < 0 ||
            prefix > (parsedNetwork.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128))
        {
            return false;
        }

        network = parsedNetwork;
        return true;
    }

    private static bool IsInNetwork(IPAddress address, IPAddress network, int prefix)
    {
        if (address.AddressFamily != network.AddressFamily)
        {
            return false;
        }

        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;

        for (var index = 0; index < fullBytes; index++)
        {
            if (addressBytes[index] != networkBytes[index])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    private static bool TryGetRemotePort(string endpoint, out int port)
    {
        port = 0;
        var separator = endpoint.LastIndexOf(':');
        return separator >= 0 &&
               int.TryParse(endpoint[(separator + 1)..], out port) &&
               port is >= 0 and <= 65535;
    }

    private static bool TryGetRemoteAddress(string endpoint, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(endpoint) || endpoint is "unknown" or "—")
        {
            return false;
        }

        var value = endpoint;
        if (value.StartsWith('['))
        {
            var closing = value.IndexOf(']');
            if (closing <= 1)
            {
                return false;
            }

            value = value[1..closing];
        }
        else
        {
            var separator = value.LastIndexOf(':');
            if (separator > 0)
            {
                value = value[..separator];
            }
        }

        if (!IPAddress.TryParse(value, out var parsed))
        {
            return false;
        }

        address = parsed;
        return true;
    }
}
