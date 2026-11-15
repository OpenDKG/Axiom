// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;

namespace Axiom.Service.Hosting.Dns;

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
