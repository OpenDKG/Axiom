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
    public async Task Malware_source_upgrades_a_duplicate_ad_rule_instead_of_skipping_it()
    {
        var ads = new PrivacyShieldSourceInfo(
            "ads",
            "Ads source",
            "https://example.test/ads",
            "MIT",
            PrivacyCategory.Ads | PrivacyCategory.Tracking,
            "test");
        var malware = new PrivacyShieldSourceInfo(
            "malware",
            "Malware source",
            "https://example.test/malware",
            "MIT",
            PrivacyCategory.Malware,
            "test");

        using var client = new HttpClient(new StubHandler(request =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    request.RequestUri!.AbsolutePath.EndsWith("malware", StringComparison.Ordinal)
                        ? "shared.example\nonly-malware.example\n"
                        : "shared.example\nads-only.example\n",
                    Encoding.UTF8,
                    "text/plain"),
            }));
        using var updater = new PrivacyShieldSourceUpdater(client);

        var result = await updater.UpdateAsync([ads, malware], CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(3, result.Rules.Count);

        var shared = result.Rules.Single(rule => rule.Domain == "shared.example");
        Assert.True(shared.Category.HasFlag(PrivacyCategory.Malware));
        Assert.True(shared.Category.HasFlag(PrivacyCategory.Ads));

        var adsOnly = result.Rules.Single(rule => rule.Domain == "ads-only.example");
        Assert.False(adsOnly.Category.HasFlag(PrivacyCategory.Malware));
        Assert.True(result.Rules.Single(rule => rule.Domain == "only-malware.example")
            .Category.HasFlag(PrivacyCategory.Malware));
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
        var path = Path.Combine(Path.GetTempPath(), $"axiom-rules-{Guid.NewGuid():N}.json");
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
            File.Delete(path);
            File.Delete(previous);
        }
    }

    [Fact]
    public async Task Updater_processes_malware_sources_before_bulk_lists()
    {
        var adsSource = new PrivacyShieldSourceInfo(
            "bulk-ads",
            "Bulk Ads",
            "https://example.test/ads.txt",
            "MIT",
            PrivacyCategory.Ads,
            "ads");
        var tifSource = new PrivacyShieldSourceInfo(
            "hagezi-tif",
            "HaGeZi TIF",
            "https://example.test/tif.txt",
            "MIT",
            PrivacyCategory.Malware,
            "tif");
        var downloadOrder = new List<string>();
        using var client = new HttpClient(new StubHandler(request =>
        {
            downloadOrder.Add(request.RequestUri!.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("bad-domain.example\n"),
            };
        }));
        using var updater = new PrivacyShieldSourceUpdater(client);

        var result = await updater.UpdateAsync([adsSource, tifSource], CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(["/tif.txt", "/ads.txt"], downloadOrder);
        Assert.Equal("hagezi-tif", Assert.Single(result.Rules).SourceId);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
