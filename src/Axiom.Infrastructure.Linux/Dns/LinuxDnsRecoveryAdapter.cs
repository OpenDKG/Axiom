// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Dns;

/// <summary>
/// Linux implementation of the service-owned network recovery DNS surface (upstream 0.11+):
/// a Windows "adapter" is a resolved link, a NetworkManager connection or the resolv.conf file.
/// The adapter id is a stable UUID of <c>backend:name</c>; an entry without explicit servers is
/// <see cref="NetworkDnsMode.Automatic"/> and is restored with <c>resolvectl revert</c> /
/// <c>ignore-auto-dns no</c>. Reads and writes share the backend with the Privacy Shield redirect.
/// </summary>
public sealed class LinuxDnsRecoveryAdapter : INetworkRecoveryDnsAdapter
{
    private readonly ILinuxDnsBackend _backend;

    public LinuxDnsRecoveryAdapter(ILinuxDnsBackend backend)
    {
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));
    }

    public static LinuxDnsRecoveryAdapter Create() =>
        new(LinuxDnsBackendDetector.Create(LinuxDnsBackendDetector.Detect(ProcessRunner.Instance), ProcessRunner.Instance));

    public static Guid LinkId(LinuxDnsBackend backend, string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"axiom.linux.dns-link:{backend}:{name}"));
        var bytes = hash.AsSpan(0, 16).ToArray();
        bytes[7] = (byte)((bytes[7] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes);
    }

    public IReadOnlyList<NetworkAdapterDnsState> CaptureDns()
    {
        IReadOnlyList<LinuxDnsLink> links;
        try
        {
            links = _backend.ListLinks();
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            throw new NetworkRecoveryPlatformException("dns_capture_failed", $"Resolver links could not be enumerated: {exception.Message}", exception);
        }

        return links.Select(link => ToState(_backend.Kind, link)).ToList();
    }

    public void ApplyDns(NetworkAdapterDnsState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.AdapterId == Guid.Empty || string.IsNullOrWhiteSpace(state.InterfaceAlias))
        {
            throw new NetworkRecoveryPlatformException("dns_adapter_invalid", "The saved link identity is empty.");
        }

        if (LinkId(_backend.Kind, state.InterfaceAlias) != state.AdapterId)
        {
            throw new NetworkRecoveryPlatformException(
                "dns_adapter_invalid",
                $"The saved identifier does not belong to link '{state.InterfaceAlias}' on the {_backend.Kind} backend.");
        }

        ValidateFamily(state.Ipv4Mode, state.Ipv4Servers, AddressFamily.InterNetwork, "IPv4");
        ValidateFamily(state.Ipv6Mode, state.Ipv6Servers, AddressFamily.InterNetworkV6, "IPv6");

        var current = _backend.ListLinks().FirstOrDefault(link => string.Equals(link.Name, state.InterfaceAlias, StringComparison.Ordinal));
        var expected = ExpectedServers(state);
        if (current is not null && SameServers(current.Servers, expected))
        {
            return;
        }

        var domains = current?.Domains.Where(domain => domain != ResolvedDnsBackend.RouteAllDomain).ToList() ?? [];
        if (!_backend.SetDns(state.InterfaceAlias, expected, domains))
        {
            throw new NetworkRecoveryPlatformException("dns_apply_failed", $"The resolver of '{state.InterfaceAlias}' could not be changed.");
        }

        FlushDnsCache();

        var after = _backend.ListLinks().FirstOrDefault(link => string.Equals(link.Name, state.InterfaceAlias, StringComparison.Ordinal));
        if (expected.Count > 0 && (after is null || !SameServers(after.Servers, expected)))
        {
            throw new NetworkRecoveryPlatformException("dns_verify_failed", $"Link '{state.InterfaceAlias}' did not read back with the saved DNS configuration.");
        }
    }

    public void FlushDnsCache() => _backend.FlushCache();

    /// <summary>True when any link's resolvers are loopback only (the stub 127.0.0.53 of resolved is not a link server).</summary>
    public bool AnyAdapterUsesLoopbackDns()
    {
        try
        {
            return _backend.ListLinks().Any(link => LinuxDnsConfigurator.IsLoopbackOnly(link.Servers));
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            return false;
        }
    }

    public static NetworkAdapterDnsState ToState(LinuxDnsBackend backend, LinuxDnsLink link)
    {
        ArgumentNullException.ThrowIfNull(link);
        var ipv4 = new List<string>();
        var ipv6 = new List<string>();
        foreach (var server in link.Servers)
        {
            var percent = server.IndexOf('%', StringComparison.Ordinal);
            if (!IPAddress.TryParse(percent > 0 ? server[..percent] : server, out var address))
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
            AdapterId = LinkId(backend, link.Name),
            InterfaceAlias = link.Name,
            Description = $"{backend}: {link.Description}",
            Ipv4Mode = ipv4.Count > 0 ? NetworkDnsMode.Static : NetworkDnsMode.Automatic,
            Ipv6Mode = ipv6.Count > 0 ? NetworkDnsMode.Static : NetworkDnsMode.Automatic,
            Ipv4Servers = ipv4,
            Ipv6Servers = ipv6,
        };
    }

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

    private static void ValidateFamily(NetworkDnsMode mode, IReadOnlyList<string> servers, AddressFamily family, string familyName)
    {
        if (mode == NetworkDnsMode.Automatic)
        {
            if (servers.Count != 0)
            {
                throw new NetworkRecoveryPlatformException("dns_state_invalid", $"An automatic {familyName} entry must not carry servers.");
            }

            return;
        }

        if (servers.Count == 0 || servers.Any(server => !IPAddress.TryParse(server, out var address) || address.AddressFamily != family))
        {
            throw new NetworkRecoveryPlatformException("dns_state_invalid", $"The saved static {familyName} servers are invalid.");
        }
    }

    // Order-sensitive like the Windows and macOS adapters.
    private static bool SameServers(IReadOnlyList<string> left, IReadOnlyList<string> right) =>
        left.Count == right.Count &&
        left.Select(Normalize).SequenceEqual(right.Select(Normalize), StringComparer.OrdinalIgnoreCase);

    private static string Normalize(string server)
    {
        var percent = server.IndexOf('%', StringComparison.Ordinal);
        var text = percent > 0 ? server[..percent] : server;
        return IPAddress.TryParse(text, out var address) ? address.ToString() : server.Trim();
    }
}
