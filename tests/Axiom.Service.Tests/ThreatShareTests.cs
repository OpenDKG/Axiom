// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Threat;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class ThreatShareTests
{
    [Fact]
    public void Only_malware_blocks_requested_by_an_agent_become_candidates()
    {
        var ads = new PrivacyShieldBlockedEvent("ads.example.com", PrivacyCategory.Ads, DateTimeOffset.UtcNow);
        Assert.Null(ThreatShareController.CreateFromBlocked(ads));

        var malwareFromBrowser = new PrivacyShieldBlockedEvent(
            "evil.example.com",
            PrivacyCategory.Malware,
            DateTimeOffset.UtcNow)
        {
            AppName = "chrome.exe",
            AppPath = @"C:\Program Files\Google\Chrome\chrome.exe",
        };
        Assert.Null(ThreatShareController.CreateFromBlocked(malwareFromBrowser));

        var malwareFromAgent = new PrivacyShieldBlockedEvent(
            "Evil.Example.COM.",
            PrivacyCategory.Malware,
            DateTimeOffset.UtcNow)
        {
            AppName = "node.exe",
            AppPath = @"C:\Users\me\.opencode\bin\node.exe",
        };

        var candidate = ThreatShareController.CreateFromBlocked(malwareFromAgent);

        Assert.NotNull(candidate);
        Assert.Equal("domain", candidate!.IndicatorType);
        Assert.Equal("evil.example.com", ThreatShareVocabulary.Normalize("domain", candidate.Value));
        Assert.Equal("malware-delivery", candidate.Reason);
        Assert.Equal("fetched-by-tool", candidate.Context);
        Assert.Equal(ThreatShareSource.PrivacyShield, candidate.Source);
    }

    [Fact]
    public async Task Queue_deduplicates_and_persists_pending_candidates()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-threat-share", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "queue.json");

        try
        {
            var store = new ThreatShareStore(path);
            await using var controller = new ThreatShareController(store);

            var request = new ThreatShareEnqueueRequest
            {
                IndicatorType = "domain",
                Value = "Evil.Example.",
                Reason = "malware-delivery",
                Context = "fetched-by-tool",
                Source = ThreatShareSource.PrivacyShield,
                Detail = "blocked for opencode",
            };

            controller.Enqueue(request);
            controller.Enqueue(request with { Value = "evil.example" });
            controller.Enqueue(request with { Reason = "advertising" });
            controller.Enqueue(request with { Context = "blocked-by-dns" });
            await controller.FlushAsync(CancellationToken.None);

            var saved = store.Load();

            var item = Assert.Single(saved);
            Assert.Equal(ThreatShareState.Pending, item.State);
            Assert.Equal("ioc:domain:evil.example", item.Candidate.Id);
            Assert.Equal("evil.example", item.Candidate.Value);

            // A restarted service reads the same queue instead of re-proposing what was dismissed.
            var reloaded = new ThreatShareStore(path).Load();
            Assert.Single(reloaded);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
