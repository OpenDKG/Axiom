// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.Windows.Dns;

/// <summary>
/// Windows behaviour of Privacy Shield DNS: upstreams from the adapters, IP Helper attribution,
/// no redirect from the service (the desktop app changes adapter DNS behind a UAC prompt) and the
/// supplied fail-safe restore.
/// </summary>
public sealed class WindowsPrivacyDnsPlatform(Func<bool> restoreIfNeeded) : IPrivacyDnsPlatform
{
    public IDnsAppAttributor? Attributor { get; } = new ProcessDnsAppAttributor(new WindowsDnsProcessLookup());

    public string NoUpstreamWarning =>
        "No non-loopback Windows DNS server was found; using fallback upstream DNS. " +
        "Set an explicit upstream address if this network requires a local resolver.";

    public IReadOnlyList<IPEndPoint> DiscoverUpstreams() => SystemDnsResolver.ResolveSystemDns();

    public string? OnResolverStarted(int port) => null;

    public bool RestoreIfNeeded() => restoreIfNeeded();
}
