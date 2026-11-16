// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Privacy;

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
    /// <summary>
    /// Non-loopback system resolvers to forward allowed queries to. The shared controller passes
    /// them through <see cref="DnsUpstream.UpgradeEndpoints"/>, so a known public resolver on port
    /// 53 is queried over RFC 8484 DoH on every platform; anything else stays plain UDP/TCP.
    /// </summary>
    IReadOnlyList<IPEndPoint> DiscoverUpstreams();

    /// <summary>
    /// Whether the running resolver should re-run <see cref="DiscoverUpstreams"/> periodically and
    /// on upstream failure and swap the proxy's upstreams live (macOS: the daemon owns the redirect,
    /// so a Wi-Fi/VPN change would otherwise leave dead upstreams behind 127.0.0.1). Windows keeps
    /// discovering once at start, as before.
    /// </summary>
    bool RediscoversUpstreams => false;

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

    /// <summary>
    /// Adapter DNS persistence (upstream v0.23.3, Windows only): called after the resolver was
    /// (re)configured and at worker start with whether a resolver is running and the current
    /// settings. The Windows service, when it runs as LocalSystem, keeps the preferred or
    /// default-route adapter pointed at the loopback resolver or restores it
    /// (<c>PreferredAdapterAlias</c>, <c>AutoPointAdapterDns</c>). The default does nothing: on other
    /// platforms these two settings are not implemented and never change system DNS, whatever
    /// their value; the platform's own redirect is <see cref="OnResolverStarted"/>.
    /// </summary>
    void EnsureConfiguredAdapterDns(bool resolverRunning, PrivacyShieldSettings settings)
    {
    }

    /// <summary>
    /// Whether <see cref="EnsureConfiguredAdapterDns"/> is implemented on this platform. False
    /// means <c>PreferredAdapterAlias</c> / <c>AutoPointAdapterDns</c> are accepted and stored but
    /// have no effect, and a client must not present them as active.
    /// </summary>
    bool SupportsAdapterDnsPersistence => false;

    /// <summary>
    /// Error of the last <see cref="EnsureConfiguredAdapterDns"/> that tried to point an adapter at
    /// the resolver (upstream v0.54: surfaced as the shield's last error when none is set). Null
    /// when that call succeeded, did nothing, or on platforms without adapter DNS persistence.
    /// </summary>
    string? AdapterDnsError => null;
}

/// <summary>No redirect, no attribution, no discovery (tests and unsupported hosts).</summary>
public sealed class NullPrivacyDnsPlatform : IPrivacyDnsPlatform
{
    public static NullPrivacyDnsPlatform Instance { get; } = new();

    public IDnsAppAttributor? Attributor => null;

    public string NoUpstreamWarning =>
        "No non-loopback system DNS server was found; using encrypted DoH fallback upstream DNS. " +
        "Set an explicit upstream address if this network requires a local resolver.";

    public IReadOnlyList<IPEndPoint> DiscoverUpstreams() => [];

    public string? OnResolverStarted(int port) => null;

    public bool RestoreIfNeeded() => false;
}
