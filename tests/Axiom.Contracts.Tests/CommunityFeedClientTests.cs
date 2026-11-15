// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using Axiom.Contracts.Community;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class CommunityFeedClientTests
{
    private const string Hash = "44D88612FEA8A8F36DE82E1278ABB02F2C4B4B0F9B0B0B0B0B0B0B0B0B0B0B0B";

    [Fact]
    public async Task Feed_fetch_sends_bearer_and_parses_valid_entries()
    {
        HttpRequestMessage? captured = null;
        var handler = new StubHandler(request =>
        {
            captured = request;
            return Json(HttpStatusCode.OK, $$"""
                {
                  "entries": [
                    {
                      "sha256": "{{Hash}}",
                      "name": "example.exe",
                      "verdict": "suspicious",
                      "source": "community",
                      "updatedUtc": "2026-11-03T20:00:00Z"
                    },
                    { "sha256": "not-a-hash" }
                  ]
                }
                """);
        });
        using var http = new HttpClient(handler);
        using var client = new CommunityFeedClient(http);

        var result = await client.FetchAsync("https://feed.example/entries.json", "token-1", CancellationToken.None);

        var entry = Assert.Single(result.Entries);
        Assert.Equal(Hash, entry.Sha256);
        Assert.Equal("example.exe", entry.Name);
        Assert.Equal("suspicious", entry.Verdict);
        Assert.NotNull(captured);
        Assert.Equal("Bearer", captured!.Headers.Authorization!.Scheme);
        Assert.Equal("token-1", captured.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task Malformed_entry_shapes_are_skipped()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {
              "entries": [
                { "sha256": 123 },
                { "sha256": { "value": "44D88612FEA8A8F36DE82E1278ABB02F2C4B4B0F9B0B0B0B0B0B0B0B0B0B0B0B" } },
                { "sha256": ["44D88612FEA8A8F36DE82E1278ABB02F2C4B4B0B0B0B0B0B0B0B0B0B0B0B0B0B"] },
                { "sha256": "not-a-hash" }
              ]
            }
            """));
        using var http = new HttpClient(handler);
        using var client = new CommunityFeedClient(http);

        var result = await client.FetchAsync("https://feed.example/entries.json", null, CancellationToken.None);

        Assert.Empty(result.Entries);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("\"text\"")]
    [InlineData("null")]
    public async Task Non_object_root_is_reported_as_invalid_feed(string body)
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var http = new HttpClient(handler);
        using var client = new CommunityFeedClient(http);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            client.FetchAsync("https://feed.example/entries.json", null, CancellationToken.None));
    }

    [Fact]
    public async Task Non_https_feed_is_rejected_before_a_request()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{\"entries\":[]}"));
        using var http = new HttpClient(handler);
        using var client = new CommunityFeedClient(http);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.FetchAsync("http://feed.example/entries.json", null, CancellationToken.None));
    }

    [Fact]
    public async Task Plain_text_sha256_feed_parses_hashes_and_ignores_comments()
    {
        var secondHash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"# comment line\n; another comment\nnot-a-hash\n{Hash.ToLowerInvariant()}\nsha256:{secondHash} malware.exe\n",
                Encoding.UTF8,
                "text/plain"),
        });
        using var http = new HttpClient(handler);
        using var client = new CommunityFeedClient(http);

        var result = await client.FetchAsync("https://botvrij.example/ioclist.sha256.raw", null, CancellationToken.None);

        Assert.Equal(2, result.Entries.Count);
        Assert.Equal(Hash, result.Entries[0].Sha256);
        Assert.Equal("malware", result.Entries[0].Verdict);
        Assert.Equal("botvrij.example", result.Entries[0].Source);
        Assert.Equal(secondHash, result.Entries[1].Sha256);
    }

    [Fact]
    public async Task Plain_text_feed_without_hashes_is_rejected_as_invalid_feed()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<html><body>not hashes</body></html>", Encoding.UTF8, "text/html"),
        });
        using var http = new HttpClient(handler);
        using var client = new CommunityFeedClient(http);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            client.FetchAsync("https://feed.example/hashes.txt", null, CancellationToken.None));
    }

    [Fact]
    public async Task Multi_url_feed_merges_and_deduplicates_entries_up_to_limit()
    {
        var secondHash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        var handler = new StubHandler(request =>
        {
            var body = request.RequestUri!.AbsolutePath.EndsWith("one.json", StringComparison.Ordinal)
                ? $$"""{"entries":[{"sha256":"{{Hash}}","name":"first.exe","verdict":"malicious","source":"feed-one"}]}"""
                : $"{Hash.ToLowerInvariant()}\n{secondHash}\n";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "text/plain"),
            };
        });
        using var http = new HttpClient(handler);
        using var client = new CommunityFeedClient(http);

        var result = await client.FetchAsync(
            "https://one.example/one.json; https://two.example/hashes.txt",
            null,
            CancellationToken.None);

        Assert.Equal(2, result.Entries.Count);
        Assert.Equal("first.exe", result.Entries[0].Name);
        Assert.Equal(secondHash, result.Entries[1].Sha256);
    }

    [Fact]
    public void Catalog_presets_use_https_or_starter_urls_only()
    {
        var presets = CommunityFeedCatalog.Presets;

        Assert.NotEmpty(presets);
        Assert.Equal(
            presets.Count,
            presets.Select(p => p.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var preset in presets)
        {
            var parts = preset.Url.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert.NotEmpty(parts);
            Assert.All(parts, part => Assert.True(
                part.Equals("axiom://starter", StringComparison.OrdinalIgnoreCase) ||
                part.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
                part));
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) => new(status)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
