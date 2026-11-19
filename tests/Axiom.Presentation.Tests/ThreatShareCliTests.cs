// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Threat;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatShareCliTests
{
    [Theory]
    [InlineData("Report shared with the community", ThreatShareReportStatus.Shared)]
    [InlineData("Already shared with the community", ThreatShareReportStatus.AlreadyShared)]
    [InlineData("Daily report cap reached", ThreatShareReportStatus.CapReached)]
    [InlineData("the indicator was rejected by policy", ThreatShareReportStatus.Rejected)]
    [InlineData("node offline: cannot connect to the local DKG node", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("hermes: 'blackbox' is not a `hermes` command.", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("Failed to load plugin 'blackbox': load timed out after 10s", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("ModuleNotFoundError: No module named '_cffi_backend'", ThreatShareReportStatus.RetryableFailure)]
    [InlineData("unexpected output after a completed run", ThreatShareReportStatus.UnknownOutcome)]
    public void Reporter_output_is_classified_without_guessing(string text, ThreatShareReportStatus expected)
    {
        var result = ThreatShareCli.Classify(text, exitCode: 0);

        Assert.Equal(expected, result.Status);
        Assert.Equal(expected == ThreatShareReportStatus.UnknownOutcome, result.Ambiguous);
    }

    [Fact]
    public void A_reporter_that_never_ran_is_retryable_and_not_ambiguous()
    {
        Assert.True(ThreatShareCli.IsUnavailable("hermes: 'blackbox' is not a `hermes` command."));
        Assert.False(ThreatShareCli.IsUnavailable("Report shared with the community."));

        var result = ThreatShareCli.Classify("No module named '_cffi_backend'", exitCode: 1);

        Assert.Equal(ThreatShareReportStatus.RetryableFailure, result.Status);
        Assert.False(result.Ambiguous);
        Assert.False(result.Submitted);
    }

    [Fact]
    public void An_unknown_completed_run_is_ambiguous_rather_than_retryable()
    {
        var result = ThreatShareCli.Classify(string.Empty, exitCode: 3);

        Assert.Equal(ThreatShareReportStatus.UnknownOutcome, result.Status);
        Assert.True(result.Ambiguous);
        Assert.False(result.Submitted);
        Assert.Contains("exit code 3", result.Outcome, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReportAsync_refuses_unpublishable_candidates_before_invoking_cli()
    {
        var cliInvoked = false;
        var cli = new ThreatShareCli(() =>
        {
            cliInvoked = true;
            return "hermes.exe";
        });

        var unknownReason = await cli.ReportAsync(
            Candidate(reason: "unknown", eligibility: ThreatSharePublicationEligibility.NeedsOperatorReview),
            CancellationToken.None);
        Assert.Equal(ThreatShareReportStatus.Rejected, unknownReason.Status);
        Assert.False(cliInvoked);

        var localOnly = await cli.ReportAsync(
            Candidate(reason: "command-and-control", eligibility: ThreatSharePublicationEligibility.LocalOnly),
            CancellationToken.None);
        Assert.Equal(ThreatShareReportStatus.Rejected, localOnly.Status);
        Assert.False(cliInvoked);

        var knownVerified = await cli.ReportAsync(
            Candidate(
                reason: "command-and-control",
                eligibility: ThreatSharePublicationEligibility.NeedsOperatorReview,
                novelty: ThreatShareNoveltyStatus.KnownVerified),
            CancellationToken.None);
        Assert.Equal(ThreatShareReportStatus.Rejected, knownVerified.Status);
        Assert.False(cliInvoked);
    }

    [Theory]
    [InlineData("Retraction shared for: ioc:domain:evil.example", ThreatShareReportStatus.Retracted)]
    [InlineData("Invalid retraction: unknown id", ThreatShareReportStatus.Rejected)]
    [InlineData("Retraction FAILED: node offline", ThreatShareReportStatus.RetryableFailure)]
    public void Retract_output_is_classified_accurately(string text, ThreatShareReportStatus expected)
    {
        var result = ThreatShareCli.ClassifyRetract(text, exitCode: 1);

        Assert.Equal(expected, result.Status);
    }

    [Fact]
    public void InspectLocalGraphNovelty_sandbox_and_reporter_key_digest_are_strictly_read_only()
    {
        var dir = Path.Combine(Path.GetTempPath(), "axiom-threat-cli", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var now = new DateTimeOffset(2026, 11, 14, 4, 0, 0, TimeSpan.Zero);
            var rulesetPath = Path.Combine(dir, "ruleset.json");
            File.WriteAllText(
                rulesetPath,
                $$"""
                {
                  "synced_at": {{now.AddMinutes(-10).ToUnixTimeSeconds()}},
                  "graph_threats": [
                    { "identifier": "ioc:domain:verified.example" }
                  ],
                  "community": {
                    "ioc:domain:reported.example": { "stage": "reported", "disputed": "no" },
                    "ioc:domain:disputed.example": { "stage": "disputed", "disputed": "yes" }
                  },
                  "curator_revoked": [ "ioc:domain:revoked.example" ]
                }
                """);

            Assert.Equal(
                ThreatShareNoveltyStatus.KnownVerified,
                ThreatShareCli.InspectLocalGraphNovelty("ioc:domain:verified.example", dir, now));
            Assert.Equal(
                ThreatShareNoveltyStatus.PreviouslyReportedCommunity,
                ThreatShareCli.InspectLocalGraphNovelty("ioc:domain:reported.example", dir, now));
            Assert.Equal(
                ThreatShareNoveltyStatus.Disputed,
                ThreatShareCli.InspectLocalGraphNovelty("ioc:domain:disputed.example", dir, now));
            Assert.Equal(
                ThreatShareNoveltyStatus.Revoked,
                ThreatShareCli.InspectLocalGraphNovelty("ioc:domain:revoked.example", dir, now));
            Assert.Equal(
                ThreatShareNoveltyStatus.PotentiallyNewLocalOnly,
                ThreatShareCli.InspectLocalGraphNovelty("ioc:domain:unseen.example", dir, now));
            Assert.Equal(
                ThreatShareNoveltyStatus.Unknown,
                ThreatShareCli.InspectLocalGraphNovelty("ioc:domain:unseen.example", dir, now.AddHours(48)));

            File.WriteAllText(Path.Combine(dir, "config.yaml"), "plugins:\n  entries:\n    blackbox:\n      community_sandbox: true\n");
            Assert.True(ThreatShareCli.IsSandboxModeEnabled(dir, environmentOverride: string.Empty));
            Assert.False(ThreatShareCli.IsSandboxModeEnabled(dir, environmentOverride: "false"));

            var keyPath = Path.Combine(dir, "reporter_key.pem");
            File.WriteAllBytes(keyPath, "test-ed25519-private-material"u8.ToArray());
            var digestBefore = ThreatShareCli.ComputeReporterKeySha256(dir);
            var digestAfter = ThreatShareCli.ComputeReporterKeySha256(dir);
            Assert.False(string.IsNullOrWhiteSpace(digestBefore));
            Assert.Equal(digestBefore, digestAfter);
            Assert.Equal("test-ed25519-private-material", File.ReadAllText(keyPath));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void InspectLocalGraphNovelty_handles_case_insensitive_keys_and_out_of_range_timestamps()
    {
        var dir = Path.Combine(Path.GetTempPath(), "axiom-threat-cli", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var rulesetPath = Path.Combine(dir, "ruleset.json");
            File.WriteAllText(
                rulesetPath,
                """
                {
                  "synced_at": 1e20,
                  "kill_list": { "ioc:domain:revoked.example": true },
                  "ioc": { "verified.example": { "severity": "high" } },
                  "community": { "ioc:domain:disputed.example": { "disputed": "yes" } }
                }
                """);

            Assert.Equal(
                ThreatShareNoveltyStatus.Revoked,
                ThreatShareCli.InspectLocalGraphNovelty("IOC:DOMAIN:REVOKED.EXAMPLE", dir));
            Assert.Equal(
                ThreatShareNoveltyStatus.KnownVerified,
                ThreatShareCli.InspectLocalGraphNovelty("IOC:DOMAIN:VERIFIED.EXAMPLE", dir));
            Assert.Equal(
                ThreatShareNoveltyStatus.Disputed,
                ThreatShareCli.InspectLocalGraphNovelty("IOC:DOMAIN:DISPUTED.EXAMPLE", dir));
            Assert.Equal(
                ThreatShareNoveltyStatus.Unknown,
                ThreatShareCli.InspectLocalGraphNovelty("ioc:domain:unseen.example", dir));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static ThreatShareCandidate Candidate(
        string reason,
        ThreatSharePublicationEligibility eligibility,
        ThreatShareNoveltyStatus novelty = ThreatShareNoveltyStatus.Unknown) => new()
        {
            Id = "ioc:domain:c2.example.org",
            IndicatorType = "domain",
            Value = "c2.example.org",
            Reason = reason,
            Context = "in-tool-output",
            Source = ThreatShareSource.AiAnalyst,
            PublicationEligibility = eligibility,
            NoveltyStatus = novelty,
        };
}
