// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;

namespace Axiom.Infrastructure.Windows.Dns;

/// <summary>
/// Chooses the DNS server list written to an adapter when it is pointed at the Privacy Shield
/// loopback resolver. The resolver always comes first, and the adapter's previous servers stay
/// behind it as a fallback: if the resolver stops or hangs, Windows fails over and the machine
/// keeps name resolution instead of losing the network.
/// </summary>
public static class DnsAdapterPlan
{
    public const int DefaultMaxFallbacks = 2;

    /// <summary>
    /// Builds the ordered server list for one address family. Addresses of the other family,
    /// loopback entries and duplicates are dropped, so pointing an adapter at the resolver twice
    /// does not stack 127.0.0.1 on itself.
    /// </summary>
    public static IReadOnlyList<string> Build(
        string resolverAddress,
        IEnumerable<string>? existingAddresses,
        int maxFallbacks = DefaultMaxFallbacks)
    {
        if (!IPAddress.TryParse(resolverAddress, out var resolver))
        {
            throw new ArgumentException("The resolver address is not a valid IP address.", nameof(resolverAddress));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(maxFallbacks);

        var family = resolver.AddressFamily;
        var servers = new List<string> { resolver.ToString() };

        foreach (var text in existingAddresses ?? [])
        {
            if (servers.Count > maxFallbacks)
            {
                break;
            }

            if (!IPAddress.TryParse(text, out var address) ||
                address.AddressFamily != family ||
                IPAddress.IsLoopback(address) ||
                IPAddress.Any.Equals(address) ||
                IPAddress.IPv6Any.Equals(address))
            {
                continue;
            }

            if (servers.Any(server => IPAddress.Parse(server).Equals(address)))
            {
                continue;
            }

            servers.Add(address.ToString());
        }

        return servers;
    }

    /// <summary>True when the plan has a resolver plus at least one non-loopback fallback.</summary>
    public static bool HasFallback(IReadOnlyList<string> servers) => servers.Count > 1;
}
