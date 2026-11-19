// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Threat;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatSharePreflightTests
{
    private static ThreatShareCandidate Candidate(
        string type = "domain",
        string value = "c2.bad-host-c2.net",
        string detail = "fetched by the agent") =>
        new()
        {
            Id = $"ioc:{type}:{value}",
            IndicatorType = type,
            Value = value,
            Reason = "command-and-control",
            Context = "fetched-by-tool",
            Source = Axiom.Contracts.Threat.ThreatShareSource.AiAnalyst,
            Detail = detail,
            EvidenceClass = ThreatShareEvidenceClass.ReproducibleAttackArtifact,
            ProofGrade = ThreatShareProofGrade.Reproduced,
        };

    [Fact]
    public void A_novel_public_indicator_in_manual_mode_is_ready()
    {
        var preflight = ThreatSharePreflight.Evaluate(
            Candidate(), sharingEnabled: true, automaticSharingOff: true,
            rulesetJson: """{"rules":[]}""");

        Assert.True(preflight.Ready);
        Assert.Empty(preflight.Failures);
    }

    [Theory]
    [InlineData("domain", "eicar.test-host.net")]
    [InlineData("domain", "example.com")]
    [InlineData("domain", "doubleclick.net")]
    [InlineData("domain", "ads.doubleclick.net")]
    [InlineData("domain", "someone.github.io")]
    [InlineData("url", "https://cdn.jsdelivr.net")]
    [InlineData("url", "https://x.trycloudflare.com")]
    public void Synthetic_tracking_and_shared_hosts_are_refused(string type, string value)
    {
        var preflight = ThreatSharePreflight.Evaluate(
            Candidate(type, value), true, true, rulesetJson: string.Empty);

        Assert.False(preflight.Ready);
        var category = Assert.Single(preflight.Failures, check => check.Name == "category");
        Assert.False(category.Passed);
    }

    [Theory]
    [InlineData("44d88612fea8a8f36de82e1278abb02f")]
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")]
    public void The_eicar_test_file_is_never_shared(string hash)
    {
        var preflight = ThreatSharePreflight.Evaluate(
            Candidate("hash", hash), true, true, rulesetJson: string.Empty);

        Assert.False(preflight.Ready);
        Assert.Contains(preflight.Failures, check => check.Name == "category");
    }

    [Fact]
    public void An_indicator_already_in_the_ruleset_fails_novelty()
    {
        const string ruleset = """{"entries":[{"id":"ioc:domain:c2.bad-host-c2.net"}]}""";

        var preflight = ThreatSharePreflight.Evaluate(Candidate(), true, true, ruleset);

        Assert.False(preflight.Ready);
        var novelty = Assert.Single(preflight.Failures, check => check.Name == "novelty");
        Assert.False(novelty.Passed);
    }

    [Fact]
    public void Manual_consent_and_the_separate_automatic_sharing_gate_are_required()
    {
        var preflight = ThreatSharePreflight.Evaluate(
            Candidate(), false, false, rulesetJson: null);

        Assert.False(preflight.Ready);
        Assert.Contains("sharing", preflight.FailureText, StringComparison.Ordinal);
        Assert.Contains("Blackbox automatic sharing", preflight.FailureText, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("c2.bad-host-c2.net", true)]
    [InlineData("a.c2.bad-host-c2.net", true)]
    [InlineData("notbad-host-c2.net", false)]
    public void Host_suffix_matching_does_not_use_plain_suffixes(string host, bool expected)
    {
        Assert.Equal(expected, ThreatSharePreflight.IsHostOrSubdomain(host, "bad-host-c2.net"));
    }

    [Fact]
    public void A_candidate_outside_the_closed_vocabulary_is_refused()
    {
        var candidate = Candidate() with { Reason = "because" };

        var preflight = ThreatSharePreflight.Evaluate(candidate, true, true, null);

        Assert.False(preflight.Ready);
        Assert.Contains(preflight.Failures, check => check.Name == "reason");
    }

    [Theory]
    [InlineData("url", "https://raw.githubusercontent.com")]
    [InlineData("domain", "cdn.azureedge.net")]
    [InlineData("domain", "assets.storage.googleapis.com")]
    [InlineData("domain", "tenant.blob.core.windows.net")]
    public void Cloud_object_stores_and_major_cdns_are_refused(string type, string value)
    {
        var preflight = ThreatSharePreflight.Evaluate(
            Candidate(type, value), sharingEnabled: true, automaticSharingOff: true,
            rulesetJson: string.Empty);

        Assert.False(preflight.Ready);
        var category = Assert.Single(preflight.Failures, check => check.Name == "category");
        Assert.False(category.Passed);
    }
}
