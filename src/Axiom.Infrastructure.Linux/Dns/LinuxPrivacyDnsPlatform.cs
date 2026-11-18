// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using Axiom.Infrastructure.Unix.Interop;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.Linux.Dns;

/// <summary>Privacy Shield platform hooks on Linux: upstream discovery, redirect on start, fail-safe restore, /proc attribution.</summary>
public sealed class LinuxPrivacyDnsPlatform : IPrivacyDnsPlatform
{
    private readonly LinuxDnsConfigurator _configurator;

    public LinuxPrivacyDnsPlatform(LinuxDnsConfigurator configurator, IDnsAppAttributor? attributor)
    {
        _configurator = configurator ?? throw new ArgumentNullException(nameof(configurator));
        Attributor = attributor;
    }

    public static LinuxPrivacyDnsPlatform Create(LinuxServicePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var backend = LinuxDnsBackendDetector.Create(LinuxDnsBackendDetector.Detect(ProcessRunner.Instance), ProcessRunner.Instance);
        return new LinuxPrivacyDnsPlatform(
            new LinuxDnsConfigurator(backend, paths.DnsBackupFile),
            OperatingSystem.IsLinux() ? new ProcessDnsAppAttributor(new LinuxDnsProcessLookup()) : null);
    }

    public IDnsAppAttributor? Attributor { get; }

    public string NoUpstreamWarning =>
        "No non-loopback DNS server was found in the resolver configuration (resolvectl/nmcli/resolv.conf) or the saved backup; " +
        "using fallback upstream DNS. Set an explicit upstream address if this network requires a local resolver.";

    public IReadOnlyList<IPEndPoint> DiscoverUpstreams() => _configurator.DiscoverUpstreams();

    public bool RediscoversUpstreams => true;

    public string? OnResolverStarted(int port)
    {
        if (port != 53)
        {
            // Neither resolved nor resolv.conf carry a port; only a resolver on 53 can be the system DNS.
            return string.Create(
                CultureInfo.InvariantCulture,
                $"The resolver listens on port {port}; Linux resolver configuration can only use port 53, so system DNS was not changed.");
        }

        return _configurator.Redirect().Error;
    }

    public bool RestoreIfNeeded()
    {
        var changed = _configurator.RestoreIfNeeded();
        if (_configurator.LastRestoreError is { } error)
        {
            Console.Error.WriteLine("Privacy Shield DNS: " + error);
        }

        return changed;
    }

    /// <summary>Why the last restore could not put every link back, or null (journal-logged).</summary>
    public string? LastRestoreError => _configurator.LastRestoreError;
}
