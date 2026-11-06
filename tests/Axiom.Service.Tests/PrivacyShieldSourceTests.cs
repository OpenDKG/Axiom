// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using Axiom.Contracts.Privacy;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class PrivacyShieldSourceTests
{
    [Fact]
    public async Task Catalogued_source_is_downloaded_parsed_and_normalized()
    {
        var source = new PrivacyShieldSourceInfo(
            "test",
            "Test source",
            "https://example.test/list",
            "MIT",
            PrivacyCategory.Ads,
            "test");
        using var client = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "0.0.0.0 ads.example\n*.tracker.example\nbad..example\n",
                Encoding.UTF8,
                "text/plain"),
        }));
        using var updater = new PrivacyShieldSourceUpdater(client);

        var result = await updater.UpdateAsync([source], CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(2, result.Rules.Count);
        Assert.Contains(result.Rules, rule => rule.Domain == "ads.example");
        Assert.Contains(result.Rules, rule => rule.Domain == "tracker.example");
        Assert.Equal(2, result.Sources.Single().Entries);
    }

    [Fact]
    public async Task Failed_source_does_not_produce_a_partial_update()
    {
        var source = new PrivacyShieldSourceInfo(
            "test",
            "Test source",
            "https://example.test/list",
            "MIT",
            PrivacyCategory.Ads,
            "test");
        using var client = new HttpClient(new StubHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        using var updater = new PrivacyShieldSourceUpdater(client);

        var result = await updater.UpdateAsync([source], CancellationToken.None);

        Assert.False(result.Success);
        Assert.Empty(result.Rules);
        Assert.NotNull(result.Sources.Single().Error);
    }

    [Fact]
    public void Rule_store_round_trips_and_keeps_previous_snapshot()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"axiom-rules-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "rules.json");
        var previous = path + ".previous";
        try
        {
            var store = new PrivacyShieldRuleStore(path);
            var first = new[]
            {
                new PrivacyShieldStoredRule(
                    "first.example",
                    "test",
                    PrivacyCategory.Ads,
                    DateTimeOffset.UtcNow),
            };
            var second = new[]
            {
                new PrivacyShieldStoredRule(
                    "second.example",
                    "test",
                    PrivacyCategory.Tracking,
                    DateTimeOffset.UtcNow),
            };

            Assert.True(store.Save(first));
            Assert.True(store.Save(second));

            Assert.Equal("second.example", Assert.Single(store.Load()).Domain);
            Assert.True(File.Exists(previous));
            Assert.Contains("first.example", File.ReadAllText(previous), StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
