// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.Windows.Dns;

/// <summary>
/// Read-only discovery of the current Windows DNS servers for Privacy Shield forwarding. Parsing
/// of upstream DNS/DoH targets is platform-neutral and lives in <see cref="DnsUpstream"/> (with
/// <see cref="DnsUpstreamTarget"/>); the members below forward to it unchanged.
/// </summary>
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
        DnsUpstream.TryParse(value, out endpoint);

    public static bool TryParseUpstreamTarget(string? value, out DnsUpstreamTarget? target) =>
        DnsUpstream.TryParseTarget(value, out target);

    public static IReadOnlyList<DnsUpstreamTarget> UpgradeEndpoints(IReadOnlyList<IPEndPoint> endpoints) =>
        DnsUpstream.UpgradeEndpoints(endpoints);

    public static bool TryGetKnownDohUri(IPAddress address, out Uri? dohUri) =>
        DnsUpstream.TryGetKnownDohUri(address, out dohUri);

    public static bool TryResolveBootstrapAddress(string? host, out IPAddress? bootstrapIp) =>
        DnsUpstream.TryResolveBootstrapAddress(host, out bootstrapIp);
}
