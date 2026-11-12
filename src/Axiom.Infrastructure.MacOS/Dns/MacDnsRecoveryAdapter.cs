// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Dns;

/// <summary>
/// macOS implementation of the network recovery DNS surface. A Windows "adapter" is a macOS
/// network service (<c>networksetup -listallnetworkservices</c>): the service name is the alias,
/// its device (<c>en0</c>) the description, and the adapter id a stable UUID derived from the
/// service name, because <c>networksetup</c> does not expose the service UUID. A service with no
/// DNS override (<c>There aren't any DNS Servers set</c>) is <see cref="NetworkDnsMode.Automatic"/>
/// and is restored with <c>-setdnsservers &lt;service&gt; Empty</c>; a static list is split by
/// address family and written back verbatim. Reads and writes go through
/// <see cref="MacDnsConfigurator"/>, so the Privacy Shield redirect and recovery share one tool path.
/// </summary>
public sealed class MacDnsRecoveryAdapter : INetworkRecoveryDnsAdapter
{
    private const int ReadAttempts = 4;

    private readonly MacDnsConfigurator _configurator;

    public MacDnsRecoveryAdapter(MacDnsConfigurator configurator)
    {
        _configurator = configurator ?? throw new ArgumentNullException(nameof(configurator));
    }

    public static MacDnsRecoveryAdapter Create(MacServicePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return new MacDnsRecoveryAdapter(new MacDnsConfigurator(ProcessRunner.Instance, paths.DnsBackupFile));
    }

    /// <summary>Stable identity of a network service: a version-5 style UUID of its name.</summary>
    public static Guid ServiceId(string serviceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes("axiom.macos.network-service:" + serviceName));
        var bytes = hash.AsSpan(0, 16).ToArray();
        bytes[7] = (byte)((bytes[7] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes);
    }

    public IReadOnlyList<NetworkAdapterDnsState> CaptureDns()
    {
        IReadOnlyList<NetworkServiceEntry> services;
        try
        {
            services = _configurator.ListServices();
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_capture_failed",
                $"Network services could not be enumerated: {exception.Message}",
                exception);
        }

        var devices = _configurator.ListServiceDevices();
        var adapters = new List<NetworkAdapterDnsState>();
        foreach (var service in services.Where(service => service.Enabled))
        {
            var servers = ReadServers(service.Name)
                ?? throw new NetworkRecoveryPlatformException(
                    "dns_capture_failed",
                    $"DNS servers of network service '{service.Name}' could not be read.");

            devices.TryGetValue(service.Name, out var device);
            adapters.Add(ToState(service.Name, device ?? string.Empty, servers));
        }

        return adapters;
    }

    public void ApplyDns(NetworkAdapterDnsState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.AdapterId == Guid.Empty || string.IsNullOrWhiteSpace(state.InterfaceAlias))
        {
            throw new NetworkRecoveryPlatformException(
                "dns_adapter_invalid",
                "The saved network service identity is empty.");
        }

        if (ServiceId(state.InterfaceAlias) != state.AdapterId)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_adapter_invalid",
                $"The saved identifier does not belong to network service '{state.InterfaceAlias}'.");
        }

        ValidateFamily(state.Ipv4Mode, state.Ipv4Servers, AddressFamily.InterNetwork, "IPv4");
        ValidateFamily(state.Ipv6Mode, state.Ipv6Servers, AddressFamily.InterNetworkV6, "IPv6");

        var current = ReadServers(state.InterfaceAlias);
        if (current is null)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_adapter_missing",
                $"Network service '{state.InterfaceAlias}' is not present or its DNS could not be read.");
        }

        var expected = ExpectedServers(state);
        if (SameServers(current, expected))
        {
            return;
        }

        if (!_configurator.SetDnsServers(state.InterfaceAlias, expected))
        {
            throw new NetworkRecoveryPlatformException(
                "dns_apply_failed",
                $"networksetup could not change the DNS of '{state.InterfaceAlias}'.");
        }

        FlushDnsCache();

        var after = ReadServers(state.InterfaceAlias)
            ?? throw new NetworkRecoveryPlatformException(
                "dns_verify_missing",
                $"Network service '{state.InterfaceAlias}' could not be read after the DNS restore.");

        if (!SameServers(after, expected))
        {
            throw new NetworkRecoveryPlatformException(
                "dns_verify_failed",
                $"Network service '{state.InterfaceAlias}' did not read back with the saved DNS configuration.");
        }
    }

    public void FlushDnsCache() => _configurator.FlushCache();

    /// <summary>
    /// True when the system resolver configuration (what <c>/etc/resolv.conf</c> mirrors from the
    /// primary network service) points at a loopback address. Same probe as Windows, no tool call.
    /// </summary>
    public bool AnyAdapterUsesLoopbackDns()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
                                  adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Any(adapter => adapter.GetIPProperties().DnsAddresses.Any(IPAddress.IsLoopback));
        }
        catch (Exception exception) when (exception is NetworkInformationException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    /// <summary>Pure mapping of a <c>networksetup -getdnsservers</c> result to the shared model.</summary>
    public static NetworkAdapterDnsState ToState(string serviceName, string device, IReadOnlyList<string> servers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        ArgumentNullException.ThrowIfNull(servers);

        var ipv4 = new List<string>();
        var ipv6 = new List<string>();
        foreach (var server in servers)
        {
            if (!IPAddress.TryParse(server, out var address))
            {
                continue;
            }

            var text = address.ToString();
            var list = address.AddressFamily == AddressFamily.InterNetworkV6 ? ipv6 : ipv4;
            if (!list.Contains(text, StringComparer.OrdinalIgnoreCase))
            {
                list.Add(text);
            }
        }

        return new NetworkAdapterDnsState
        {
            AdapterId = ServiceId(serviceName),
            InterfaceAlias = serviceName,
            Description = device ?? string.Empty,
            Ipv4Mode = ipv4.Count > 0 ? NetworkDnsMode.Static : NetworkDnsMode.Automatic,
            Ipv6Mode = ipv6.Count > 0 ? NetworkDnsMode.Static : NetworkDnsMode.Automatic,
            Ipv4Servers = ipv4,
            Ipv6Servers = ipv6,
        };
    }

    /// <summary>The <c>-setdnsservers</c> argument list for a saved state (empty = <c>Empty</c>).</summary>
    public static IReadOnlyList<string> ExpectedServers(NetworkAdapterDnsState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var servers = new List<string>();
        if (state.Ipv4Mode == NetworkDnsMode.Static)
        {
            servers.AddRange(state.Ipv4Servers);
        }

        if (state.Ipv6Mode == NetworkDnsMode.Static)
        {
            servers.AddRange(state.Ipv6Servers);
        }

        return servers;
    }

    private IReadOnlyList<string>? ReadServers(string service)
    {
        for (var attempt = 1; ; attempt++)
        {
            var servers = _configurator.GetDnsServers(service);
            if (servers is not null || attempt >= ReadAttempts)
            {
                return servers;
            }

            Thread.Sleep(_configurator.ReadRetryDelay);
        }
    }

    private static void ValidateFamily(
        NetworkDnsMode mode,
        IReadOnlyList<string> servers,
        AddressFamily family,
        string familyName)
    {
        if (mode == NetworkDnsMode.Automatic)
        {
            if (servers.Count != 0)
            {
                throw new NetworkRecoveryPlatformException(
                    "dns_state_invalid",
                    $"An automatic {familyName} entry must not carry servers.");
            }

            return;
        }

        if (servers.Count == 0 ||
            servers.Any(server => !IPAddress.TryParse(server, out var address) || address.AddressFamily != family))
        {
            throw new NetworkRecoveryPlatformException(
                "dns_state_invalid",
                $"The saved static {familyName} servers are invalid.");
        }
    }

    // Order-sensitive, like upstream's WindowsDnsRecoveryAdapter and NetworkRecoveryController (v0.12.0):
    // resolver order is part of the saved state, and networksetup preserves the order it was given.
    private static bool SameServers(IReadOnlyList<string> left, IReadOnlyList<string> right) =>
        left.Count == right.Count &&
        left.Select(Normalize).SequenceEqual(right.Select(Normalize), StringComparer.OrdinalIgnoreCase);

    private static string Normalize(string server) =>
        IPAddress.TryParse(server, out var address) ? address.ToString() : server.Trim();
}
