// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Privacy;
using Axiom.Infrastructure.Windows.Dns;
using Axiom.Service.Hosting.Dns;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class WindowsPrivacyDnsPlatformTests
{
    [Fact]
    public void No_upstream_warning_is_the_text_upstream_shows_on_windows()
    {
        IPrivacyDnsPlatform platform = new WindowsPrivacyDnsPlatform(() => false);

        Assert.Equal(
            "No non-loopback Windows DNS server was found; using encrypted DoH fallback upstream DNS. " +
            "Set an explicit upstream address if this network requires a local resolver.",
            platform.NoUpstreamWarning);
        Assert.False(platform.RediscoversUpstreams);
        Assert.Null(platform.OnResolverStarted(53));
    }

    /// <summary>
    /// Upstream v0.23.3 PrivacyShieldController.EnsureConfiguredAdapterDns, now behind the seam:
    /// not LocalSystem -> nothing; resolver running, enabled, port 53 and (AutoPointAdapterDns or a
    /// preferred alias) -> EnsureAdapterPointed(alias); otherwise, when disabled or auto-point is
    /// off -> RestoreIfNeeded; else nothing. The expected column is upstream's code read as a table.
    /// </summary>
    [Theory]
    // system running enabled port  auto   alias        => pointed restored
    [InlineData(false, true, true, 53, true, "Ethernet", false, false)]
    [InlineData(true, true, true, 53, true, "", true, false)]
    [InlineData(true, true, true, 53, false, "Wi-Fi", true, false)]
    [InlineData(true, true, true, 53, true, "Wi-Fi", true, false)]
    [InlineData(true, true, true, 53, false, "", false, true)]
    [InlineData(true, true, true, 53, false, "   ", false, true)]
    [InlineData(true, true, true, 5353, true, "", false, false)]
    [InlineData(true, true, true, 5353, false, "Wi-Fi", false, true)]
    [InlineData(true, false, true, 53, true, "", false, false)]
    [InlineData(true, false, true, 53, false, "Wi-Fi", false, true)]
    [InlineData(true, true, false, 53, true, "Wi-Fi", false, true)]
    [InlineData(true, false, false, 53, false, "", false, true)]
    public void Adapter_dns_persistence_is_upstreams_decision(
        bool system, bool running, bool enabled, int port, bool autoPoint, string alias, bool pointed, bool restored)
    {
        var settings = new PrivacyShieldSettings
        {
            Enabled = enabled,
            Port = port,
            AutoPointAdapterDns = autoPoint,
            PreferredAdapterAlias = alias,
        };

        // Upstream's method body with its statics as locals.
        var expectedPointed = false;
        var expectedRestored = false;
        if (system)
        {
            if (running &&
                settings.Enabled &&
                settings.Port == 53 &&
                (settings.AutoPointAdapterDns || !string.IsNullOrWhiteSpace(settings.PreferredAdapterAlias)))
            {
                expectedPointed = true;
            }
            else if (!settings.Enabled || !settings.AutoPointAdapterDns)
            {
                expectedRestored = true;
            }
        }

        Assert.Equal((pointed, restored), (expectedPointed, expectedRestored));

        var restores = 0;
        var pointedAliases = new List<string?>();
        IPrivacyDnsPlatform platform = new WindowsPrivacyDnsPlatform(
            () => { restores++; return true; },
            () => system,
            adapterAlias => { pointedAliases.Add(adapterAlias); return true; });

        platform.EnsureConfiguredAdapterDns(running, settings);

        Assert.True(platform.SupportsAdapterDnsPersistence);
        Assert.Equal(pointed ? [alias] : [], pointedAliases);
        Assert.Equal(restored ? 1 : 0, restores);
    }

    /// <summary>
    /// Upstream v0.64.0: after pointing the adapter the controller reports
    /// <c>PrivacyDnsFailSafe.LastError</c>. The seam returns it only from the pointing branch.
    /// </summary>
    [Fact]
    public void Adapter_error_is_returned_only_after_pointing_the_adapter()
    {
        var restores = 0;
        IPrivacyDnsPlatform platform = new WindowsPrivacyDnsPlatform(
            () => { restores++; return true; },
            () => true,
            _ => false,
            () => "Adapter 'Ethernet' has no valid IPv4 fallback DNS/gateway yet.");

        var pointing = platform.EnsureConfiguredAdapterDns(
            true,
            new PrivacyShieldSettings { Enabled = true, Port = 53, AutoPointAdapterDns = true });
        var restoring = platform.EnsureConfiguredAdapterDns(false, new PrivacyShieldSettings());

        Assert.Equal("Adapter 'Ethernet' has no valid IPv4 fallback DNS/gateway yet.", pointing);
        Assert.Null(restoring);
        Assert.Equal(1, restores);
        Assert.Null(((IPrivacyDnsPlatform)NullPrivacyDnsPlatform.Instance).EnsureConfiguredAdapterDns(
            true,
            new PrivacyShieldSettings { Enabled = true, Port = 53, AutoPointAdapterDns = true }));
    }

    /// <summary>Without the LocalSystem probe and the adapter action (tests, tools) nothing is touched.</summary>
    [Fact]
    public void Adapter_dns_persistence_needs_the_service_helpers()
    {
        var restores = 0;
        IPrivacyDnsPlatform platform = new WindowsPrivacyDnsPlatform(() => { restores++; return true; });

        platform.EnsureConfiguredAdapterDns(true, new PrivacyShieldSettings { Enabled = true, AutoPointAdapterDns = true });
        platform.EnsureConfiguredAdapterDns(false, new PrivacyShieldSettings());

        Assert.False(platform.SupportsAdapterDnsPersistence);
        Assert.Equal(0, restores);
    }

    /// <summary>The seam's default (every non-Windows platform): the settings are accepted and nothing happens.</summary>
    [Fact]
    public void Default_seam_member_never_changes_system_dns()
    {
        IPrivacyDnsPlatform platform = NullPrivacyDnsPlatform.Instance;

        platform.EnsureConfiguredAdapterDns(
            true,
            new PrivacyShieldSettings { Enabled = true, Port = 53, AutoPointAdapterDns = true, PreferredAdapterAlias = "en0" });

        Assert.False(platform.SupportsAdapterDnsPersistence);
    }

    /// <summary>The members upstream added to SystemDnsResolver in v0.23.3/v0.24.0 forward to the shared parser unchanged.</summary>
    [Fact]
    public void New_upstream_members_forward_to_the_shared_parser()
    {
        Assert.Equal(DnsUpstream.DefaultDohTargets(), SystemDnsResolver.DefaultDohTargets());
        Assert.Equal(
            ["https://1.1.1.1/dns-query (DoH)", "https://9.9.9.9/dns-query (DoH)"],
            SystemDnsResolver.DefaultDohTargets().Select(target => target.DisplayText));

        foreach (var value in new[] { "1.1.1.1, 9.9.9.9", "https://dns.quad9.net/dns-query;udp://192.168.1.1", "1.1.1.1,,", "1.1.1.1, nonsense", "127.0.0.1", "", null })
        {
            var windows = SystemDnsResolver.TryParseUpstreamTargets(value, out var fromWindows);
            var shared = DnsUpstream.TryParseTargets(value, out var fromShared);
            Assert.Equal(shared, windows);
            Assert.Equal(fromShared, fromWindows);
        }

        // Adapter filtering stays Windows code: site-local dummies, multicast, loopback and wildcards are dropped.
        Assert.Equal(
            [new IPEndPoint(IPAddress.Parse("192.168.1.1"), 53), new IPEndPoint(IPAddress.Parse("2606:4700:4700::1111"), 53)],
            SystemDnsResolver.FilterSystemDnsAddresses(
            [
                IPAddress.Parse("fec0:0:0:ffff::1"), IPAddress.Parse("192.168.1.1"), IPAddress.Loopback, IPAddress.Any,
                IPAddress.Parse("ff02::fb"), IPAddress.Parse("2606:4700:4700::1111"), IPAddress.Parse("192.168.1.1"),
            ]));
    }
}
