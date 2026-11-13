// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Privacy;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.Windows.Dns;

/// <summary>
/// Windows behaviour of Privacy Shield DNS: upstreams from the adapters, IP Helper attribution,
/// the supplied fail-safe restore and, since upstream v0.23.3, adapter DNS persistence when the
/// service runs as LocalSystem (<see cref="EnsureConfiguredAdapterDns"/>). The desktop app can
/// still change adapter DNS behind a UAC prompt. The three delegates are the service's own
/// Windows helpers (<c>PrivacyDnsFailSafe.RestoreIfNeeded</c>,
/// <c>MachineStateSecurity.IsRunningAsSystem</c>, <c>PrivacyDnsFailSafe.EnsureAdapterPointed</c>).
/// </summary>
public sealed class WindowsPrivacyDnsPlatform(
    Func<bool> restoreIfNeeded,
    Func<bool>? isRunningAsSystem = null,
    Func<string?, bool>? ensureAdapterPointed = null) : IPrivacyDnsPlatform
{
    public IDnsAppAttributor? Attributor { get; } = new ProcessDnsAppAttributor(new WindowsDnsProcessLookup());

    public string NoUpstreamWarning =>
        "No non-loopback Windows DNS server was found; using encrypted DoH fallback upstream DNS. " +
        "Set an explicit upstream address if this network requires a local resolver.";

    public IReadOnlyList<IPEndPoint> DiscoverUpstreams() => SystemDnsResolver.ResolveSystemDns();

    public string? OnResolverStarted(int port) => null;

    public bool RestoreIfNeeded() => restoreIfNeeded();

    public bool SupportsAdapterDnsPersistence => isRunningAsSystem is not null && ensureAdapterPointed is not null;

    /// <summary>
    /// Upstream's <c>PrivacyShieldController.EnsureConfiguredAdapterDns</c> (v0.23.3), moved here
    /// unchanged: <c>_server is not null</c> is <paramref name="resolverRunning"/>,
    /// <c>_settings</c> is <paramref name="settings"/>.
    /// </summary>
    public void EnsureConfiguredAdapterDns(bool resolverRunning, PrivacyShieldSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (isRunningAsSystem is null || ensureAdapterPointed is null || !isRunningAsSystem())
        {
            return;
        }

        if (resolverRunning &&
            settings.Enabled &&
            settings.Port == 53 &&
            (settings.AutoPointAdapterDns || !string.IsNullOrWhiteSpace(settings.PreferredAdapterAlias)))
        {
            ensureAdapterPointed(settings.PreferredAdapterAlias);
            return;
        }

        if (!settings.Enabled || !settings.AutoPointAdapterDns)
        {
            restoreIfNeeded();
        }
    }
}
