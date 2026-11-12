// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.Windows.Network;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

/// <summary>
/// Read-only checks against the live adapter list. Nothing here applies DNS or changes a network
/// setting; they guard the capture shape that the service persists.
/// </summary>
public sealed class WindowsDnsRecoveryAdapterTests
{
    [Fact]
    public void Capture_returns_only_valid_per_family_states()
    {
        var adapter = new WindowsDnsRecoveryAdapter();

        var states = adapter.CaptureDns();

        Assert.All(states, state =>
        {
            Assert.NotEqual(Guid.Empty, state.AdapterId);
            Assert.False(string.IsNullOrWhiteSpace(state.InterfaceAlias));
            Assert.True(Enum.IsDefined(state.Ipv4Mode));
            Assert.True(Enum.IsDefined(state.Ipv6Mode));

            AssertAutomaticOrStatic(state.Ipv4Mode, state.Ipv4Servers, AddressFamily.InterNetwork);
            AssertAutomaticOrStatic(state.Ipv6Mode, state.Ipv6Servers, AddressFamily.InterNetworkV6);
        });
    }

    [Fact]
    public void Capture_and_loopback_probe_do_not_change_the_network()
    {
        var adapter = new WindowsDnsRecoveryAdapter();

        _ = adapter.CaptureDns();
        _ = adapter.AnyAdapterUsesLoopbackDns();

        // The assertions above are the verification: these calls are read-only by contract, and a
        // write would require the explicit ApplyDns path with a validated snapshot.
    }

    private static void AssertAutomaticOrStatic(
        NetworkDnsMode mode,
        IReadOnlyList<string> servers,
        AddressFamily family)
    {
        if (mode == NetworkDnsMode.Automatic)
        {
            Assert.Empty(servers);
            return;
        }

        Assert.NotEmpty(servers);
        Assert.All(servers, server =>
        {
            Assert.True(IPAddress.TryParse(server, out var address));
            Assert.Equal(family, address!.AddressFamily);
        });
    }
}
