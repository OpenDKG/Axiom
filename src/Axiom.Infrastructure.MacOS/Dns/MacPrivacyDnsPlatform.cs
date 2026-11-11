// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.MacOS.Dns;

/// <summary>
/// Privacy Shield on macOS. Unlike Windows (where the desktop app changes adapter DNS behind a UAC
/// prompt), the root daemon owns the whole cycle: when the resolver is running it points every
/// enabled network service at 127.0.0.1 with networksetup, and it restores the saved servers when
/// the resolver stops, Privacy Shield is disabled, or the daemon shuts down. A crash in between is
/// repaired by <see cref="RestoreIfNeeded"/> at the next start.
/// </summary>
public sealed class MacPrivacyDnsPlatform : IPrivacyDnsPlatform
{
    private readonly MacDnsConfigurator _configurator;

    public MacPrivacyDnsPlatform(MacDnsConfigurator configurator, IDnsAppAttributor? attributor)
    {
        _configurator = configurator ?? throw new ArgumentNullException(nameof(configurator));
        Attributor = attributor;
    }

    public static MacPrivacyDnsPlatform Create(MacServicePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return new MacPrivacyDnsPlatform(
            new MacDnsConfigurator(ProcessRunner.Instance, paths.DnsBackupFile),
            OperatingSystem.IsMacOS() ? new ProcessDnsAppAttributor(new MacDnsProcessLookup()) : null);
    }

    public IDnsAppAttributor? Attributor { get; }

    public string NoUpstreamWarning =>
        "No non-loopback DNS server was found in scutil --dns or the saved network settings; using " +
        "fallback upstream DNS. Set an explicit upstream address if this network requires a local resolver.";

    public IReadOnlyList<IPEndPoint> DiscoverUpstreams() => _configurator.DiscoverUpstreams();

    public bool RediscoversUpstreams => true;

    public string? OnResolverStarted(int port)
    {
        if (port != 53)
        {
            // macOS resolver configuration has no port; only a resolver on 53 can be the system DNS.
            return string.Create(
                CultureInfo.InvariantCulture,
                $"The resolver listens on port {port}; macOS can only use a resolver on port 53, so system DNS was not changed.");
        }

        var result = _configurator.Redirect();
        return result.Error;
    }

    public bool RestoreIfNeeded() => _configurator.RestoreIfNeeded();
}
