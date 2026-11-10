// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Windows.Dns;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class DnsAdapterPlanTests
{
    private static readonly string[] RouterDns = ["192.168.0.1"];
    private static readonly string[] ResolverThenRouter = ["127.0.0.1", "192.168.0.1"];
    private static readonly string[] MixedFamilies = ["::1", "127.0.0.1", "fe80::1", "192.168.1.1"];
    private static readonly string[] ResolverThenSecond = ["127.0.0.1", "192.168.1.1"];
    private static readonly string[] DuplicateRouter = ["192.168.0.1", "192.168.0.1"];
    private static readonly string[] ThreeServers = ["192.168.0.1", "192.168.1.1", "10.0.0.1"];
    private static readonly string[] LoopbackAndJunk = ["127.0.0.1", string.Empty, "not-an-ip"];
    private static readonly string[] ResolverOnly = ["127.0.0.1"];
    private static readonly string[] Ipv6Input = ["192.168.0.1", "fe80::1"];
    private static readonly string[] ResolverThenIpv6 = ["::1", "fe80::1"];

    [Fact]
    public void Resolver_comes_first_and_the_previous_server_stays_as_fallback()
    {
        var servers = DnsAdapterPlan.Build("127.0.0.1", RouterDns);

        Assert.Equal(ResolverThenRouter, servers);
        Assert.True(DnsAdapterPlan.HasFallback(servers));
    }

    [Fact]
    public void Other_address_family_and_loopback_entries_are_dropped()
    {
        var servers = DnsAdapterPlan.Build("127.0.0.1", MixedFamilies);

        Assert.Equal(ResolverThenSecond, servers);
    }

    [Fact]
    public void Duplicate_fallback_is_not_repeated()
    {
        var servers = DnsAdapterPlan.Build("127.0.0.1", DuplicateRouter);

        Assert.Equal(ResolverThenRouter, servers);
    }

    [Fact]
    public void Fallback_count_is_capped()
    {
        var servers = DnsAdapterPlan.Build("127.0.0.1", ThreeServers, maxFallbacks: 1);

        Assert.Equal(ResolverThenRouter, servers);
    }

    [Fact]
    public void Resolver_only_plan_reports_no_fallback()
    {
        var servers = DnsAdapterPlan.Build("127.0.0.1", LoopbackAndJunk);

        Assert.Equal(ResolverOnly, servers);
        Assert.False(DnsAdapterPlan.HasFallback(servers));
    }

    [Fact]
    public void Invalid_resolver_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => DnsAdapterPlan.Build("127.0.0.1:53", RouterDns));
    }

    [Fact]
    public void Ipv6_plan_keeps_ipv6_fallback()
    {
        var servers = DnsAdapterPlan.Build("::1", Ipv6Input);

        Assert.Equal(ResolverThenIpv6, servers);
    }
}
