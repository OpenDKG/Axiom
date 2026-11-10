// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;

namespace Axiom.Service.Hosting.Dns;

/// <summary>
/// Platform seam of Privacy Shield: upstream discovery, query attribution and the system DNS
/// redirect with its fail-safe. Windows never redirects from the service (the desktop helper does,
/// with consent) but restores adapters that still point at the stopped resolver; macOS points every
/// enabled network service at the loopback resolver while it runs and restores the saved servers
/// when it stops.
/// </summary>
public interface IPrivacyDnsPlatform
{
    /// <summary>Non-loopback system resolvers to forward allowed queries to.</summary>
    IReadOnlyList<IPEndPoint> DiscoverUpstreams();

    /// <summary>Optional attribution of blocked queries to the querying app.</summary>
    IDnsAppAttributor? Attributor { get; }

    /// <summary>Warning shown when <see cref="DiscoverUpstreams"/> found nothing and fallbacks are used.</summary>
    string NoUpstreamWarning { get; }

    /// <summary>
    /// Called after the resolver started listening on 127.0.0.1:<paramref name="port"/>. Returns an
    /// optional warning (for example when the system DNS could not be redirected).
    /// </summary>
    string? OnResolverStarted(int port);

    /// <summary>
    /// Fail-safe: when the resolver is not running but the system still sends DNS to the loopback
    /// resolver, restore the saved DNS configuration. Returns true when something was changed or
    /// attempted.
    /// </summary>
    bool RestoreIfNeeded();
}

/// <summary>No redirect, no attribution, no discovery (tests and unsupported hosts).</summary>
public sealed class NullPrivacyDnsPlatform : IPrivacyDnsPlatform
{
    public static NullPrivacyDnsPlatform Instance { get; } = new();

    public IDnsAppAttributor? Attributor => null;

    public string NoUpstreamWarning =>
        "No non-loopback system DNS server was found; using fallback upstream DNS. " +
        "Set an explicit upstream address if this network requires a local resolver.";

    public IReadOnlyList<IPEndPoint> DiscoverUpstreams() => [];

    public string? OnResolverStarted(int port) => null;

    public bool RestoreIfNeeded() => false;
}
