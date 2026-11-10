// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Axiom.Infrastructure.Windows.Dns;

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

    public static bool TryParseUpstream(string? value, out IPEndPoint? endpoint) =>
        Axiom.Service.Hosting.Dns.DnsUpstream.TryParse(value, out endpoint);
}
