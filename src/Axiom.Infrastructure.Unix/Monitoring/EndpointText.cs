// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Axiom.Infrastructure.Unix.Monitoring;

/// <summary>Endpoint text of the Connections page: <c>1.2.3.4:443</c>, <c>[::1]:53</c>, <c>—</c> for none.</summary>
public static class EndpointText
{
    public const string None = "—";

    public static string Format(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.AddressFamily == AddressFamily.InterNetworkV6
            ? string.Create(CultureInfo.InvariantCulture, $"[{address}]:{port}")
            : string.Create(CultureInfo.InvariantCulture, $"{address}:{port}");
    }

    public static string Format(string address, int port)
    {
        if (IPAddress.TryParse(address, out var parsed))
        {
            return Format(parsed, port);
        }

        return string.IsNullOrEmpty(address)
            ? None
            : string.Create(CultureInfo.InvariantCulture, $"{address}:{port}");
    }

    public static bool IsAny(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
    }
}
