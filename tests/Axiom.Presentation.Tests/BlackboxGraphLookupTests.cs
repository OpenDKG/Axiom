// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class BlackboxGraphLookupTests
{
    private const string BaseUrl = "http://127.0.0.1:9700";

    [Fact]
    public async Task Public_entry_is_returned_with_sources_and_reporters()
    {
        var handler = new StubHandler(_ => Found("public", "urlhaus", reporters: 2));
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, BaseUrl);

        var result = await lookup.LookupDomainAsync("Evil.Example.");

        Assert.Equal(GraphLookupKind.Public, result.Kind);
        Assert.Equal("ioc:domain:evil.example", result.Identifier);
        Assert.Contains("urlhaus", result.Sources);
        Assert.Equal(2, result.Reporters);
        Assert.Contains("Public graph entry", result.Describe(), StringComparison.Ordinal);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Local_entry_is_checked_after_public_misses()
    {
        var handler = new StubHandler(request =>
            request.RequestUri!.Query.Contains("tier=public", StringComparison.Ordinal)
                ? NotFound()
                : Found("local", "synced-rules", reporters: 0));
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, BaseUrl);

        var result = await lookup.LookupAsync("ioc:domain:evil.example");

        Assert.Equal(GraphLookupKind.Local, result.Kind);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Community_entry_is_reported_as_a_sighting_not_a_verdict()
    {
        var handler = new StubHandler(request =>
            request.RequestUri!.Query.Contains("tier=community", StringComparison.Ordinal)
                ? Found("community", "reporter-a", reporters: 3)
                : NotFound());
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, BaseUrl);

        var result = await lookup.LookupAsync("ioc:domain:evil.example");

        Assert.Equal(GraphLookupKind.Community, result.Kind);
        Assert.Contains("not a verified verdict", result.Describe(), StringComparison.Ordinal);
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task All_tiers_missing_is_unknown_not_clean()
    {
        var handler = new StubHandler(_ => NotFound());
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, BaseUrl);

        var result = await lookup.LookupAsync("ioc:domain:evil.example");

        Assert.Equal(GraphLookupKind.NotFound, result.Kind);
        Assert.Contains("Unknown, not clean", result.Describe(), StringComparison.Ordinal);
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task Dashboard_error_is_unknown_and_not_cached()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, BaseUrl);

        var result = await lookup.LookupAsync("ioc:domain:evil.example");

        Assert.Equal(GraphLookupKind.Unknown, result.Kind);
        Assert.Contains("Unknown, not clean", result.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Found_entry_without_provenance_is_not_treated_as_a_match()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {"identifier":"ioc:domain:evil.example","tier":"public","category":"ioc","sources":[],"reporters":0,"found":true}
            """));
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, BaseUrl);

        var result = await lookup.LookupAsync("ioc:domain:evil.example");

        Assert.Equal(GraphLookupKind.Unknown, result.Kind);
        Assert.Contains("no source or reporter provenance", result.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Results_are_cached_and_expire_after_the_ttl()
    {
        var now = new DateTimeOffset(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);
        var handler = new StubHandler(_ => Found("public", "urlhaus", reporters: 1));
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(
            http,
            BaseUrl,
            cacheTtl: TimeSpan.FromMinutes(5),
            clock: () => now);

        await lookup.LookupAsync("ioc:domain:evil.example");
        await lookup.LookupAsync("ioc:domain:evil.example");
        Assert.Equal(1, handler.Calls);

        now = now.AddMinutes(6);
        await lookup.LookupAsync("ioc:domain:evil.example");
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Non_loopback_endpoint_is_refused_without_a_request()
    {
        var handler = new StubHandler(_ => Found("public", "urlhaus", reporters: 1));
        using var http = new HttpClient(handler);
        using var lookup = new BlackboxGraphLookup(http, "http://example.com:9700");

        var result = await lookup.LookupAsync("ioc:domain:evil.example");

        Assert.Equal(GraphLookupKind.Unknown, result.Kind);
        Assert.Equal(0, handler.Calls);
    }

    private static HttpResponseMessage Found(string tier, string source, int reporters) => Json(
        HttpStatusCode.OK,
        $$"""
        {"identifier":"ioc:domain:evil.example","tier":"{{tier}}","category":"ioc","sources":["{{source}}"],"references":[],"found":true,"reporters":{{reporters}}}
        """);

    private static HttpResponseMessage NotFound() => Json(
        HttpStatusCode.OK,
        """{"identifier":"ioc:domain:evil.example","tier":"public","category":"ioc","sources":[],"references":[],"found":false,"reporters":0}""");

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
