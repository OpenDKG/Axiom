// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using Axiom.Contracts.Modules;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class OptionalModuleProbeTests
{
    private const string DkgUrl = "http://127.0.0.1:9200";
    private const string BlackboxUrl = "http://127.0.0.1:9700";

    [Fact]
    public async Task Dkg_status_is_connected_when_the_local_node_answers()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {"version":"10.1.0","peerId":"12D3KooExample","nodeRole":"edge","networkName":"DKG V10 Base Testnet","networkId":"7449c543ff04a550b2dafa999fe8ee577a00b212023bb4d4244e8d58a4792c7b"}
            """));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeDkgAsync(CancellationToken.None);

        Assert.True(result.IsConnected);
        Assert.Equal("CONNECTED", result.Status);
        Assert.Contains("10.1.0", result.Detail, StringComparison.Ordinal);
        Assert.Contains("edge", result.Detail, StringComparison.Ordinal);
        Assert.Contains("DKG V10 Base Testnet", result.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"status":"ok"}""")]
    [InlineData("""{"version":"10.1.0","peerId":"12D3KooExample","nodeRole":"edge"}""")]
    [InlineData("""{"version":"10.1.0","peerId":"nope","nodeRole":"edge","networkId":"7449c543ff04a550b2dafa999fe8ee577a00b212023bb4d4244e8d58a4792c7b"}""")]
    [InlineData("""{"version":"10.1.0","peerId":"12D3KooExample","nodeRole":"edge","networkId":"0000000000000000000000000000000000000000000000000000000000000000"}""")]
    public async Task Something_else_on_the_dkg_port_is_not_reported_as_connected(string body)
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeDkgAsync(CancellationToken.None);

        Assert.False(result.IsConnected);
        Assert.Equal("UNKNOWN", result.Status);
    }

    [Fact]
    public async Task Dkg_uses_the_node_blackbox_reports_when_no_standalone_node_answers()
    {
        var handler = new StubHandler(request =>
        {
            var uri = request.RequestUri!;
            if (uri.Port == 9200)
            {
                throw new HttpRequestException("refused");
            }

            if (uri.AbsolutePath == "/api/graph-status")
            {
                return Json(HttpStatusCode.OK, """
                    {"mode":"block","node_reachable":true,"dkg_url":"http://127.0.0.1:9320","sync_progress":{}}
                    """);
            }

            if (uri.Port == 9320 && uri.AbsolutePath == "/api/status")
            {
                return Json(HttpStatusCode.OK, """
                    {"version":"10.1.0","peerId":"12D3KooExample","nodeRole":"edge","networkName":"DKG V10 Base Testnet","networkId":"7449c543ff04a550b2dafa999fe8ee577a00b212023bb4d4244e8d58a4792c7b"}
                    """);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeDkgAsync(CancellationToken.None);

        Assert.True(result.IsConnected);
        Assert.Equal("CONNECTED", result.Status);
        Assert.Contains("reported by Blackbox", result.Detail, StringComparison.Ordinal);
        Assert.Contains("9320", result.Endpoint, StringComparison.Ordinal);
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
        Assert.Contains("Start button", result.Detail, StringComparison.Ordinal);
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
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {"mode":"block","node_reachable":true,"dkg_url":"http://127.0.0.1:9320","sync_progress":{"blackbox":{"state":"ready"}}}
            """));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeBlackboxAsync(CancellationToken.None);

        Assert.True(result.IsConnected);
        Assert.Equal("CONNECTED", result.Status);
        Assert.Contains("Blackbox", result.Detail, StringComparison.Ordinal);
        Assert.Contains("block", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Another_listener_on_the_blackbox_port_is_not_reported_as_connected()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """{"status":"ok"}"""));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeBlackboxAsync(CancellationToken.None);

        Assert.False(result.IsConnected);
        Assert.Equal("UNKNOWN", result.Status);
        Assert.Contains("not treated as the dashboard", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blackbox_http_error_is_not_reported_as_connected()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var http = new HttpClient(handler);
        using var probe = new OptionalModuleProbe(http, DkgUrl, BlackboxUrl);

        var result = await probe.ProbeBlackboxAsync(CancellationToken.None);

        Assert.False(result.IsConnected);
        Assert.Equal("UNKNOWN", result.Status);
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
