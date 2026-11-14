// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Axiom.Infrastructure.Windows.Dns;

/// <summary>
/// Resolved upstream DNS destination: either plain UDP/TCP or encrypted RFC 8484 DNS-over-HTTPS (DoH).
/// </summary>
public sealed record DnsUpstreamTarget(
    IPEndPoint? PlainEndpoint,
    Uri? DohUri = null,
    IPAddress? BootstrapAddress = null,
    bool FallbackToPlainAllowed = false)
{
    public bool IsDoh => DohUri is not null;

    public string DisplayText => (DohUri, PlainEndpoint) switch
    {
        ({ } doh, { } plain) when FallbackToPlainAllowed => $"{doh} (DoH, fallback {plain})",
        ({ } doh, _) => $"{doh} (DoH)",
        (null, { } plain) => plain.ToString(),
        _ => "unknown",
    };
}

/// <summary>Read-only discovery and parsing of upstream DNS/DoH targets for Privacy Shield forwarding.</summary>
public static class SystemDnsResolver
{
    private static readonly Dictionary<IPAddress, Uri> KnownDohByAddress = new()
    {
        [IPAddress.Parse("1.1.1.1")] = new Uri("https://1.1.1.1/dns-query"),
        [IPAddress.Parse("1.0.0.1")] = new Uri("https://1.0.0.1/dns-query"),
        [IPAddress.Parse("2606:4700:4700::1111")] = new Uri("https://[2606:4700:4700::1111]/dns-query"),
        [IPAddress.Parse("2606:4700:4700::1001")] = new Uri("https://[2606:4700:4700::1001]/dns-query"),
        [IPAddress.Parse("8.8.8.8")] = new Uri("https://8.8.8.8/dns-query"),
        [IPAddress.Parse("8.8.4.4")] = new Uri("https://8.8.4.4/dns-query"),
        [IPAddress.Parse("2001:4860:4860::8888")] = new Uri("https://[2001:4860:4860::8888]/dns-query"),
        [IPAddress.Parse("2001:4860:4860::8844")] = new Uri("https://[2001:4860:4860::8844]/dns-query"),
        [IPAddress.Parse("9.9.9.9")] = new Uri("https://9.9.9.9/dns-query"),
        [IPAddress.Parse("149.112.112.112")] = new Uri("https://149.112.112.112/dns-query"),
        [IPAddress.Parse("2620:fe::fe")] = new Uri("https://[2620:fe::fe]/dns-query"),
        [IPAddress.Parse("2620:fe::9")] = new Uri("https://[2620:fe::9]/dns-query"),
        [IPAddress.Parse("94.140.14.14")] = new Uri("https://94.140.14.14/dns-query"),
        [IPAddress.Parse("94.140.15.15")] = new Uri("https://94.140.15.15/dns-query"),
        [IPAddress.Parse("2a10:50c0::ad1:ff")] = new Uri("https://[2a10:50c0::ad1:ff]/dns-query"),
        [IPAddress.Parse("2a10:50c0::ad2:ff")] = new Uri("https://[2a10:50c0::ad2:ff]/dns-query"),
    };

    private static readonly Dictionary<string, IPAddress> KnownBootstrapByHost = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cloudflare-dns.com"] = IPAddress.Parse("1.1.1.1"),
        ["one.one.one.one"] = IPAddress.Parse("1.1.1.1"),
        ["dns.google"] = IPAddress.Parse("8.8.8.8"),
        ["dns.quad9.net"] = IPAddress.Parse("9.9.9.9"),
        ["dns.adguard-dns.com"] = IPAddress.Parse("94.140.14.14"),
        ["dns.adguard.com"] = IPAddress.Parse("94.140.14.14"),
    };

    public static IReadOnlyList<IPEndPoint> ResolveSystemDns(int max = 4)
    {
        try
        {
            var addresses = NetworkInterface.GetAllNetworkInterfaces()
                .Where(network => network.OperationalStatus == OperationalStatus.Up &&
                                  network.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(network => network.GetIPProperties().DnsAddresses);

            return FilterSystemDnsAddresses(addresses, max);
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    /// <summary>
    /// Filters interface DNS addresses to reachable unicast resolvers, excluding deprecated
    /// Windows IPv6 site-local dummy servers such as fec0:0:0:ffff::1/2/3.
    /// </summary>
    public static IReadOnlyList<IPEndPoint> FilterSystemDnsAddresses(
        IEnumerable<IPAddress> addresses,
        int max = 4)
    {
        return addresses
            .Where(address => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Where(address => !IPAddress.IsLoopback(address))
            .Where(address => !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
            .Where(address => !address.IsIPv6SiteLocal && !address.IsIPv6Multicast)
            .Distinct()
            .Take(Math.Clamp(max, 1, 16))
            .Select(address => new IPEndPoint(address, 53))
            .ToArray();
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

    public static bool TryParseUpstreamTarget(string? value, out DnsUpstreamTarget? target)
    {
        target = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var text = value.Trim();
        if (text.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(uri.DnsSafeHost) ||
                uri.Port <= 0)
            {
                return false;
            }

            if (IsLoopbackHost(uri.DnsSafeHost))
            {
                return false;
            }

            var builder = new UriBuilder(uri);
            if (string.IsNullOrEmpty(builder.Path) || builder.Path == "/")
            {
                builder.Path = "/dns-query";
            }

            IPAddress? bootstrapIp = null;
            if (IPAddress.TryParse(uri.DnsSafeHost, out var parsedHostIp))
            {
                bootstrapIp = parsedHostIp;
            }
            else if (TryResolveBootstrapAddress(uri.DnsSafeHost, out var knownIp))
            {
                bootstrapIp = knownIp;
            }

            target = new DnsUpstreamTarget(
                PlainEndpoint: null,
                DohUri: builder.Uri,
                BootstrapAddress: bootstrapIp,
                FallbackToPlainAllowed: false);
            return true;
        }

        if (text.StartsWith("udp://", StringComparison.OrdinalIgnoreCase) ||
            text.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
        {
            var plainText = text[6..];
            if (!TryParseUpstream(plainText, out var forcedPlain) || forcedPlain is null)
            {
                return false;
            }

            target = new DnsUpstreamTarget(forcedPlain, DohUri: null);
            return true;
        }

        if (!TryParseUpstream(text, out var endpoint) || endpoint is null)
        {
            return false;
        }

        if (endpoint.Port == 53 && TryGetKnownDohUri(endpoint.Address, out var dohUri) && dohUri is not null)
        {
            target = new DnsUpstreamTarget(
                PlainEndpoint: endpoint,
                DohUri: dohUri,
                BootstrapAddress: endpoint.Address,
                FallbackToPlainAllowed: false);
            return true;
        }

        target = new DnsUpstreamTarget(endpoint, DohUri: null);
        return true;
    }

    /// <summary>
    /// Parses one or more comma/semicolon-separated upstream entries (IP, IP:port, udp://IP, or DoH HTTPS URL).
    /// Returns false if any non-empty token is invalid.
    /// </summary>
    public static bool TryParseUpstreamTargets(string? value, out IReadOnlyList<DnsUpstreamTarget> targets)
    {
        targets = [];
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var parts = value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
        {
            return false;
        }

        var parsed = new List<DnsUpstreamTarget>(parts.Length);
        foreach (var part in parts)
        {
            if (!TryParseUpstreamTarget(part, out var single) || single is null)
            {
                return false;
            }

            parsed.Add(single);
        }

        targets = parsed;
        return true;
    }

    /// <summary>
    /// Redundant encrypted RFC 8484 DoH resolvers (Cloudflare + Quad9 on TLS port 443) used so
    /// queries cannot be read by an ISP or local router over plain UDP port 53.
    /// </summary>
    public static IReadOnlyList<DnsUpstreamTarget> DefaultDohTargets() => UpgradeEndpoints(
    [
        new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53),
        new IPEndPoint(IPAddress.Parse("9.9.9.9"), 53),
    ]);

    public static IReadOnlyList<DnsUpstreamTarget> UpgradeEndpoints(IReadOnlyList<IPEndPoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var result = new List<DnsUpstreamTarget>(endpoints.Count);
        foreach (var endpoint in endpoints)
        {
            if (endpoint.Port == 53 && TryGetKnownDohUri(endpoint.Address, out var dohUri) && dohUri is not null)
            {
                result.Add(new DnsUpstreamTarget(
                    PlainEndpoint: endpoint,
                    DohUri: dohUri,
                    BootstrapAddress: endpoint.Address,
                    FallbackToPlainAllowed: false));
            }
            else
            {
                result.Add(new DnsUpstreamTarget(endpoint, DohUri: null));
            }
        }

        return result;
    }

    public static bool TryGetKnownDohUri(IPAddress address, out Uri? dohUri)
    {
        ArgumentNullException.ThrowIfNull(address);
        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return KnownDohByAddress.TryGetValue(normalized, out dohUri);
    }

    public static bool TryResolveBootstrapAddress(string? host, out IPAddress? bootstrapIp)
    {
        bootstrapIp = null;
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var trimmed = host.Trim().Trim('[', ']');
        if (IPAddress.TryParse(trimmed, out var parsed))
        {
            bootstrapIp = parsed;
            return true;
        }

        return KnownBootstrapByHost.TryGetValue(trimmed, out bootstrapIp);
    }

    private static bool IsLoopbackHost(string host)
    {
        var trimmed = host.Trim().Trim('[', ']');
        if (string.Equals(trimmed, "localhost", StringComparison.OrdinalIgnoreCase) ||
            trimmed.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(trimmed, out var address) && IPAddress.IsLoopback(address);
    }
}
