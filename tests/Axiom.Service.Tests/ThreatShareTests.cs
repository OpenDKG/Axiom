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
    public void An_agent_tool_child_qualifies_through_its_agent_ancestor()
    {
        // A real agent shells out to curl/git/nslookup, so the DNS query belongs to the tool child
        // while the agent is an ancestor. That is still a truthful "fetched by tool" sighting.
        var viaTool = new PrivacyShieldBlockedEvent(
            "malware.example",
            PrivacyCategory.Malware,
            DateTimeOffset.UtcNow)
        {
            AppName = "nslookup.exe",
            AppPath = @"C:\Windows\System32\nslookup.exe",
            AgentName = "opencode.exe",
            AgentPath = @"C:\Users\me\AppData\Local\Programs\@openchamberelectron\resources\opencode-cli\opencode.exe",
        };

        var candidate = ThreatShareController.CreateFromBlocked(viaTool);

        Assert.NotNull(candidate);
        Assert.Contains("via opencode.exe", candidate!.Detail, StringComparison.Ordinal);
        Assert.Equal("fetched-by-tool", candidate.Context);
    }

    [Fact]
    public void A_tool_child_without_an_agent_ancestor_stays_local()
    {
        var unrelated = new PrivacyShieldBlockedEvent(
            "malware.example",
            PrivacyCategory.Malware,
            DateTimeOffset.UtcNow)
        {
            AppName = "nslookup.exe",
            AppPath = @"C:\Windows\System32\nslookup.exe",
        };

        Assert.Null(ThreatShareController.CreateFromBlocked(unrelated));
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

    [Fact]
    public async Task Transient_failure_defers_the_candidate_instead_of_rejecting_it()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-threat-share", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "queue.json");

        try
        {
            await using var controller = new ThreatShareController(new ThreatShareStore(path));
            controller.Enqueue(Candidate());
            await controller.FlushAsync(CancellationToken.None);

            var status = await controller.RecordAsync(
                new ThreatShareRecordRequest
                {
                    Id = "ioc:domain:evil.example",
                    Submitted = false,
                    Deferred = true,
                    Outcome = "the Blackbox CLI timed out",
                },
                CancellationToken.None);

            var item = Assert.Single(status.Items);
            Assert.Equal(ThreatShareState.Deferred, item.State);
            Assert.Equal(1, item.Attempts);
            Assert.NotNull(item.NextAttemptUtc);
            Assert.True(item.NextAttemptUtc > DateTimeOffset.UtcNow);
            Assert.Equal(1, status.Deferred);
            Assert.Equal(0, status.Pending);
            Assert.Contains("timed out", item.StateDetail, StringComparison.Ordinal);

            // A restarted service still sees a deferred item, not a lost one.
            var reloaded = new ThreatShareStore(path).Load();
            Assert.Equal(ThreatShareState.Deferred, Assert.Single(reloaded).State);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Policy_refusal_is_rejected_and_dismissal_clears_a_deferred_item()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-threat-share", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "queue.json");

        try
        {
            await using var controller = new ThreatShareController(new ThreatShareStore(path));
            controller.Enqueue(Candidate());
            await controller.FlushAsync(CancellationToken.None);

            var deferred = await controller.RecordAsync(
                new ThreatShareRecordRequest
                {
                    Id = "ioc:domain:evil.example",
                    Submitted = false,
                    Deferred = true,
                    Outcome = "node offline",
                },
                CancellationToken.None);
            Assert.Equal(1, deferred.Deferred);

            var dismissed = await controller.DismissAsync("ioc:domain:evil.example", CancellationToken.None);
            Assert.Equal(ThreatShareState.Dismissed, Assert.Single(dismissed.Items).State);
            Assert.Equal(0, dismissed.Deferred);

            controller.Enqueue(Candidate() with { Value = "refused.example" });
            await controller.FlushAsync(CancellationToken.None);
            var rejected = await controller.RecordAsync(
                new ThreatShareRecordRequest
                {
                    Id = "ioc:domain:refused.example",
                    Submitted = false,
                    Deferred = false,
                    Outcome = "invalid indicator",
                },
                CancellationToken.None);

            var item = Assert.Single(rejected.Items, value => value.Candidate.Value == "refused.example");
            Assert.Equal(ThreatShareState.Rejected, item.State);
            Assert.Equal("invalid indicator", item.Outcome);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static ThreatShareEnqueueRequest Candidate() => new()
    {
        IndicatorType = "domain",
        Value = "evil.example",
        Reason = "malware-delivery",
        Context = "fetched-by-tool",
        Source = ThreatShareSource.PrivacyShield,
        Detail = "blocked for opencode",
    };
}
