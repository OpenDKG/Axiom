// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using Netpetra.Contracts.Modules;
using Xunit;

namespace Netpetra.Contracts.Tests;

public sealed class OptionalModuleProbeTests
{
    private const string DkgUrl = "http://127.0.0.1:9200";
    private const string BlackboxUrl = "http://127.0.0.1:9700";

    [Fact]
    public async Task Dkg_status_is_connected_when_the_local_node_answers()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {"version":"10.0.23","peerId":"12D3KooExample","nodeRole":"edge"}
            """));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeDkgAsync(CancellationToken.None);

        Assert.True(result.IsConnected);
        Assert.Equal("CONNECTED", result.Status);
        Assert.Contains("10.0.23", result.Detail, StringComparison.Ordinal);
        Assert.Contains("edge", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dkg_status_is_not_running_when_the_connection_is_refused()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("refused"));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeDkgAsync(CancellationToken.None);

        Assert.False(result.IsConnected);
        Assert.Equal("NOT RUNNING", result.Status);
        Assert.Contains("does not start", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Non_loopback_endpoint_is_refused_without_a_request()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{}"));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, "http://example.com:9200", BlackboxUrl);

        var result = await probe.ProbeDkgAsync(CancellationToken.None);

        Assert.False(result.IsConnected);
        Assert.Equal("UNAVAILABLE", result.Status);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task Blackbox_is_connected_when_the_loopback_dashboard_answers()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{\"status\":\"ok\"}"));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeBlackboxAsync(CancellationToken.None);

        Assert.True(result.IsConnected);
        Assert.Equal("CONNECTED", result.Status);
        Assert.Contains("Blackbox", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blackbox_is_still_reported_running_when_graph_status_is_missing()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeBlackboxAsync(CancellationToken.None);

        Assert.True(result.IsConnected);
        Assert.Contains("404", result.Detail, StringComparison.Ordinal);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) => new(status)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(respond(request));
        }
    }
}
