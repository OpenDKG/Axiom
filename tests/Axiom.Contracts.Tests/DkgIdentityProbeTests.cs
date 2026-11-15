// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using Axiom.Contracts.Blackbox;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class DkgIdentityProbeTests : IDisposable
{
    private readonly string _home = Path.Combine(
        Path.GetTempPath(),
        "axiom-dkg-probe-" + Guid.NewGuid().ToString("N"));

    public DkgIdentityProbeTests()
    {
        Directory.CreateDirectory(_home);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_home, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task Uses_the_token_line_and_the_port_from_the_home()
    {
        await WriteHomeAsync("# bearer token for the local API\nabc123\n", "9320");

        var handler = new StubHandler(request =>
        {
            Assert.Equal(new Uri("http://127.0.0.1:9320/api/agent/identity"), request.RequestUri);
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal("abc123", request.Headers.Authorization?.Parameter);
            return Json(HttpStatusCode.OK, """{"agentAddress":"0xabc","agentDid":"did:dkg:agent:0xabc"}""");
        });

        var result = await DkgIdentityProbe.CheckAsync(_home, new HttpClient(handler));

        Assert.True(result.Verified);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal("0xabc", result.AgentAddress);
        Assert.Equal("did:dkg:agent:0xabc", result.AgentDid);
    }

    [Fact]
    public async Task A_401_is_reported_as_a_home_token_mismatch()
    {
        await WriteHomeAsync("# token\nabc123\n", "9320");

        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var result = await DkgIdentityProbe.CheckAsync(_home, new HttpClient(handler));

        Assert.False(result.Verified);
        Assert.Equal(401, result.StatusCode);
        Assert.Contains("different DKG homes", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_missing_auth_token_file_is_not_verified_without_a_request()
    {
        var handler = new StubHandler(_ => throw new InvalidOperationException("must not call the node"));
        var result = await DkgIdentityProbe.CheckAsync(_home, new HttpClient(handler));

        Assert.False(result.Verified);
        Assert.Contains("auth.token", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Falls_back_to_the_default_port_when_api_port_is_absent()
    {
        await WriteHomeAsync("# token\nabc123\n", port: null);

        var handler = new StubHandler(request =>
        {
            Assert.Equal(
                new Uri($"http://127.0.0.1:{DkgIdentityProbe.DefaultPort}/api/agent/identity"),
                request.RequestUri);
            return Json(HttpStatusCode.OK, """{"agentAddress":"0xabc"}""");
        });

        var result = await DkgIdentityProbe.CheckAsync(_home, new HttpClient(handler));

        Assert.True(result.Verified);
    }

    private async Task WriteHomeAsync(string tokenText, string? port)
    {
        await File.WriteAllTextAsync(Path.Combine(_home, "auth.token"), tokenText);
        if (port is not null)
        {
            await File.WriteAllTextAsync(Path.Combine(_home, "api.port"), port);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body) };

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(_respond(request));
    }
}
