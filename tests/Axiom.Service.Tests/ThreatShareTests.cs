// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Threat;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class ThreatShareTests
{
    [Fact]
    public void Privacy_shield_list_detections_have_no_share_entry_point()
    {
        // Public list matches stay local; there must be no service API that can turn a blocked
        // DNS lookup into a community report and look like independent corroboration.
        Assert.DoesNotContain(
            typeof(ThreatShareController).GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly),
            method => method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(PrivacyShieldBlockedEvent)));
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
    public async Task Ambiguous_outcome_is_unverified_and_reuses_the_submission_key()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-threat-share", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "queue.json");

        try
        {
            await using var controller = new ThreatShareController(new ThreatShareStore(path));
            controller.Enqueue(Candidate());
            await controller.FlushAsync(CancellationToken.None);

            var first = await controller.RecordAsync(
                new ThreatShareRecordRequest
                {
                    Id = "ioc:domain:evil.example",
                    Submitted = false,
                    Ambiguous = true,
                    Outcome = "the Blackbox CLI timed out after it started",
                },
                CancellationToken.None);

            var item = Assert.Single(first.Items);
            Assert.Equal(ThreatShareState.Unverified, item.State);
            Assert.Null(item.NextAttemptUtc);
            Assert.Equal(1, item.Attempts);
            Assert.False(string.IsNullOrWhiteSpace(item.SubmissionKey));
            Assert.Equal(1, first.Unverified);
            Assert.Equal(0, first.Deferred);
            Assert.Contains("may have published", item.StateDetail, StringComparison.Ordinal);

            // A restarted service keeps the same attempt key, so a retry is traceable.
            var reloaded = Assert.Single(new ThreatShareStore(path).Load());
            Assert.Equal(item.SubmissionKey, reloaded.SubmissionKey);
            Assert.Equal(ThreatShareState.Unverified, reloaded.State);

            var retry = await controller.RecordAsync(
                new ThreatShareRecordRequest
                {
                    Id = "ioc:domain:evil.example",
                    Submitted = true,
                    Outcome = "already shared",
                },
                CancellationToken.None);

            var retried = Assert.Single(retry.Items);
            Assert.Equal(ThreatShareState.Submitted, retried.State);
            Assert.Equal(item.SubmissionKey, retried.SubmissionKey);
            Assert.Equal(2, retried.Attempts);
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

    [Fact]
    public async Task RetractAsync_records_retracted_state_and_persists_eligibility_fields()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-threat-share", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "queue.json");

        try
        {
            var store = new ThreatShareStore(path);
            await using var controller = new ThreatShareController(store);
            controller.Enqueue(new ThreatShareEnqueueRequest
            {
                IndicatorType = "domain",
                Value = "github.io",
                Reason = "phishing",
                Context = "in-tool-output",
                Source = ThreatShareSource.AiAnalyst,
                Severity = "medium",
                EvidenceClass = ThreatShareEvidenceClass.HeuristicOrAiSuspected,
                ProofGrade = ThreatShareProofGrade.Observed,
            });
            await controller.FlushAsync(CancellationToken.None);

            var initial = Assert.Single(store.Load());
            Assert.Equal("medium", initial.Candidate.Severity);
            Assert.Equal(ThreatSharePublicationEligibility.NeedsEvidence, initial.Candidate.PublicationEligibility);
            Assert.Equal("SHARED_HOSTING_APEX", initial.Candidate.EligibilityReasonCode);
            Assert.False(initial.Candidate.CanPublishToCommunity);

            var submitted = await controller.RecordAsync(
                new ThreatShareRecordRequest
                {
                    Id = "ioc:domain:github.io",
                    Submitted = true,
                    Outcome = "shared",
                },
                CancellationToken.None);
            Assert.Equal(ThreatShareState.Submitted, Assert.Single(submitted.Items).State);

            var retracted = await controller.RetractAsync(
                "ioc:domain:github.io",
                string.Empty,
                CancellationToken.None);
            var retractedItem = Assert.Single(retracted.Items);
            Assert.Equal(ThreatShareState.Retracted, retractedItem.State);
            Assert.Contains("CC0 replicas", retractedItem.StateDetail, StringComparison.Ordinal);

            var reloaded = Assert.Single(new ThreatShareStore(path).Load());
            Assert.Equal(ThreatShareState.Retracted, reloaded.State);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Overflow_eviction_releases_known_ids_and_dispose_flushes_incoming()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-threat-share", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "queue.json");

        try
        {
            var store = new ThreatShareStore(path);
            await using (var controller = new ThreatShareController(store))
            {
                for (var i = 0; i < ThreatShareStore.MaxItems + 5; i++)
                {
                    controller.Enqueue(Candidate() with { Value = $"host{i}.example" });
                }

                await controller.FlushAsync(CancellationToken.None);

                // The evicted first entry (host0.example) can be re-enqueued once evicted.
                controller.Enqueue(Candidate() with { Value = "host0.example" });
            }

            var reloaded = store.Load();
            Assert.Equal(ThreatShareStore.MaxItems, reloaded.Count);
            Assert.Contains(reloaded, item => item.Candidate.Value == "host0.example");
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
