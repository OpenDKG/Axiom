// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class P0GraphLookupRegressionTests
{
    [Fact]
    public async Task LookupAsync_returns_Unknown_when_dashboard_response_exceeds_2MiB_limit()
    {
        var oversized = new string('a', (2 * 1024 * 1024) + 1024);
        using var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(oversized, Encoding.UTF8, "application/json"),
        });

        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, "http://127.0.0.1:9700");

        var result = await lookup.LookupDomainAsync("evil.example", CancellationToken.None);
        Assert.Equal(GraphLookupKind.Unknown, result.Kind);
        Assert.Contains("size limit", result.Note, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}
