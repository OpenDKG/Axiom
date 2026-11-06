// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Netpetra.Infrastructure.Windows.Dns;

/// <summary>Read-only discovery of the current Windows DNS servers for upstream forwarding.</summary>
public static class SystemDnsResolver
{
    public static IReadOnlyList<IPEndPoint> ResolveSystemDns(int max = 4)
    {
        try
        {
            var addresses = NetworkInterface.GetAllNetworkInterfaces()
                .Where(network => network.OperationalStatus == OperationalStatus.Up &&
                                  network.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(network => network.GetIPProperties().DnsAddresses)
                .Where(address => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Where(address => !IPAddress.IsLoopback(address))
                .Where(address => !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
                .Distinct()
                .Take(Math.Clamp(max, 1, 16))
                .Select(address => new IPEndPoint(address, 53))
                .ToArray();

            return addresses;
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    public static bool TryParseUpstream(string? value, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var text = value.Trim();
        var port = 53;
        var addressText = text;

        if (text.StartsWith('['))
        {
            var closing = text.IndexOf(']');
            if (closing < 0)
            {
                return false;
            }

            addressText = text[1..closing];
            if (closing + 1 < text.Length)
            {
                if (text[closing + 1] != ':' ||
                    !int.TryParse(text[(closing + 2)..], out port))
                {
                    return false;
                }
            }
        }
        else
        {
            var colon = text.LastIndexOf(':');
            if (colon > 0 && text.IndexOf(':') == colon)
            {
                addressText = text[..colon];
                if (!int.TryParse(text[(colon + 1)..], out port))
                {
                    return false;
                }
            }
        }

        if (port is < 1 or > 65535 ||
            !IPAddress.TryParse(addressText, out var address) ||
            IPAddress.IsLoopback(address))
        {
            return false;
        }

        endpoint = new IPEndPoint(address, port);
        return true;
    }
}
