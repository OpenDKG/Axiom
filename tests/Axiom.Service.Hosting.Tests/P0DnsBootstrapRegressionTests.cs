// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using Axiom.Contracts.Privacy;
using Axiom.Service.Hosting.Dns;
using Xunit;

namespace Axiom.Service.Hosting.Tests;

/// <summary>
/// Regression guard for the DoH bootstrap refresh that is already on main (commit dc10560d): the
/// connect callback reads a volatile map that is rebuilt on every target swap. The test reads that
/// map through <see cref="DnsProxyServer.CurrentDohBootstrapAddresses"/>; it opens no DoH connection.
/// </summary>
public sealed class P0DnsBootstrapRegressionTests
{
    [Fact]
    public async Task UpdateTargets_refreshes_DoH_bootstrap_address_map()
    {
        var policy = PrivacyShieldPolicy.Create(new PrivacyShieldSettings { Categories = PrivacyCategory.None });
        var initialTarget = new DnsUpstreamTarget(
            PlainEndpoint: null,
            DohUri: new Uri("https://dns.example.test/dns-query"),
            BootstrapAddress: IPAddress.Parse("1.1.1.1"));

        await using var proxy = new DnsProxyServer(
            policy,
            [initialTarget],
            port: 0,
            dohHandler: new StubHandler());

        Assert.Equal(IPAddress.Parse("1.1.1.1"), proxy.CurrentDohBootstrapAddresses["dns.example.test"]);

        var updatedTarget = new DnsUpstreamTarget(
            PlainEndpoint: null,
            DohUri: new Uri("https://doh2.example.test/dns-query"),
            BootstrapAddress: IPAddress.Parse("9.9.9.9"));
        proxy.UpdateTargets([updatedTarget]);

        Assert.False(proxy.CurrentDohBootstrapAddresses.ContainsKey("dns.example.test"));
        Assert.Equal(IPAddress.Parse("9.9.9.9"), proxy.CurrentDohBootstrapAddresses["doh2.example.test"]);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}
