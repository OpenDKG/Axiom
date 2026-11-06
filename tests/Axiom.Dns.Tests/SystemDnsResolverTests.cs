// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Dns;
using Xunit;

namespace Axiom.Dns.Tests;

public sealed class SystemDnsResolverTests
{
    [Fact]
    public void Loopback_stub_is_a_valid_upstream()
    {
        Assert.True(SystemDnsResolver.TryParseUpstream("127.0.0.53", out var endpoint));
        Assert.Equal(IPAddress.Parse("127.0.0.53"), endpoint!.Address);
        Assert.Equal(53, endpoint.Port);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    [InlineData("::ffff:127.0.0.1")]
    public void The_proxy_own_endpoint_is_rejected(string value) =>
        Assert.False(SystemDnsResolver.TryParseUpstream(value, out _));

    [Fact]
    public void Discovery_never_returns_the_proxy_own_endpoint()
    {
        Assert.DoesNotContain(
            SystemDnsResolver.ResolveSystemDns(),
            endpoint => IPAddress.IsLoopback(endpoint.Address) &&
                        (endpoint.Address.Equals(IPAddress.Loopback) ||
                         endpoint.Address.Equals(IPAddress.IPv6Loopback)));
    }
}
