// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Text;
using Axiom.Contracts.Ai;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class AiAnalystEndpointTests
{
    private const string Completion =
        """{"choices":[{"message":{"content":"{\"status\":\"INSUFFICIENT_DATA\",\"severity\":\"unknown\",\"confidence\":\"none\",\"summary\":\"no data\",\"observations\":[],\"evidenceReferences\":[],\"alternativeExplanations\":[],\"missingEvidence\":[],\"recommendedActions\":[]}"}}]}""";

    [Fact]
    public async Task Loopback_http_endpoint_is_accepted_without_a_local_provider_label()
    {
        using var handler = new StubHandler(Completion);
        using var client = new AiAnalystClient(new HttpClient(handler));

        var finding = await client.AnalyzeAsync(
            Settings("http://127.0.0.1:18080/v1"),
            "not-a-real-key",
            Evidence(),
            CancellationToken.None);

        Assert.True(handler.Called);
        Assert.Equal("INSUFFICIENT_DATA", finding.Status);
    }

    [Fact]
    public async Task Remote_http_endpoint_is_refused_before_any_request()
    {
        using var handler = new StubHandler(Completion);
        using var client = new AiAnalystClient(new HttpClient(handler));

        var finding = await client.AnalyzeAsync(
            Settings("http://example.com/v1"),
            "not-a-real-key",
            Evidence(),
            CancellationToken.None);

        Assert.False(handler.Called);
        Assert.Contains("HTTPS", finding.Error, StringComparison.OrdinalIgnoreCase);
    }

    private static AiAnalystSettings Settings(string endpoint) => new()
    {
        Enabled = true,
        Endpoint = endpoint,
        Model = "test-model",
    };

    private static AiEvidencePackage Evidence() => new(
        "1",
        DateTimeOffset.UtcNow,
        "unit-test",
        "standard",
        [],
        []);

    private sealed class StubHandler(string body) : HttpMessageHandler
    {
        public bool Called { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Called = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }
}
