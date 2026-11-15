// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;

namespace Axiom.Service.Hosting.Dns;

/// <summary>
/// Parses a user-configured upstream resolver (<c>1.2.3.4</c>, <c>1.2.3.4:5353</c>, <c>[::1]:53</c>,
/// <c>udp://IP</c>, <c>https://.../dns-query</c>) and upgrades known public resolvers to their
/// RFC 8484 DoH endpoint. Platform-neutral: the Windows <c>SystemDnsResolver</c> forwards here, the
/// Unix daemons use it directly, so every platform selects the same upstream for the same input.
/// </summary>
public static class DnsUpstream
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

    public static bool TryParse(string? value, out IPEndPoint? endpoint)
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

    public static bool TryParseTarget(string? value, out DnsUpstreamTarget? target)
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
            if (!TryParse(plainText, out var forcedPlain) || forcedPlain is null)
            {
                return false;
            }

            target = new DnsUpstreamTarget(forcedPlain, DohUri: null);
            return true;
        }

        if (!TryParse(text, out var endpoint) || endpoint is null)
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
    public static bool TryParseTargets(string? value, out IReadOnlyList<DnsUpstreamTarget> targets)
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
            if (!TryParseTarget(part, out var single) || single is null)
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

    /// <summary>
    /// Upstream targets for "no explicit upstream configured", from the platform's system
    /// resolvers: upstream's v0.24.0 selection, used at start and by every later rediscovery so the
    /// two can never disagree. With <paramref name="encryptDnsViaDoh"/> only the DoH members of the
    /// upgraded list are used, or <see cref="DefaultDohTargets"/> when there is none (a plain
    /// router or VPN resolver is not used); without it the upgraded list is returned as it is,
    /// possibly empty.
    /// </summary>
    public static IReadOnlyList<DnsUpstreamTarget> SelectSystemTargets(
        IReadOnlyList<IPEndPoint> systemEndpoints,
        bool encryptDnsViaDoh)
    {
        var systemTargets = UpgradeEndpoints(systemEndpoints);
        if (encryptDnsViaDoh)
        {
            var encryptedSystem = systemTargets.Where(item => item.IsDoh).ToArray();
            return encryptedSystem.Length > 0
                ? encryptedSystem
                : DefaultDohTargets();
        }

        return systemTargets;
    }

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
