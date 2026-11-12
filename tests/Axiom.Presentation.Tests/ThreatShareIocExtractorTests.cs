// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ai;
using Axiom.Contracts.Threat;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatShareIocExtractorTests
{
    [Fact]
    public void Structured_indicators_matching_observed_remotes_are_shared()
    {
        var finding = Finding(
            new AiIndicator { Type = "ip", Value = "8.8.8.8", Role = "malicious" },
            new AiIndicator { Type = "domain", Value = "c2.example.org", Role = "malicious" },
            new AiIndicator { Type = "url", Value = "https://c2.example.org", Role = "malicious" },
            new AiIndicator { Type = "hash", Value = Sha256, Role = "malicious" });

        var candidates = ThreatShareIocExtractor.Extract(
            finding,
            Evidence("8.8.8.8:443", "c2.example.org:443"));

        Assert.Contains(candidates, candidate => candidate.IndicatorType == "ip" && candidate.Value == "8.8.8.8");
        Assert.Contains(candidates, candidate => candidate.IndicatorType == "domain" && candidate.Value == "c2.example.org");
        Assert.Contains(candidates, candidate => candidate.IndicatorType == "url" && candidate.Value == "https://c2.example.org");
        Assert.DoesNotContain(candidates, candidate => candidate.IndicatorType == "hash");
        Assert.All(candidates, candidate =>
        {
            Assert.Equal(ThreatShareSource.AiAnalyst, candidate.Source);
            Assert.Equal("in-tool-output", candidate.Context);
            Assert.Contains("Axiom observed", candidate.Detail, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void Url_path_is_not_shared_by_default()
    {
        var finding = Finding(
            new AiIndicator
            {
                Type = "url",
                Value = "https://c2.example.org/private/account?token=abc",
                Role = "malicious",
            });

        Assert.Empty(ThreatShareIocExtractor.Extract(finding, Evidence("c2.example.org:443")));
    }

    [Fact]
    public void Prose_and_recommended_actions_are_never_scanned()
    {
        var finding = Finding();
        finding = finding with
        {
            Summary = "The process fetched https://payload.example.net/drop.bin and contacted 6.6.6.6.",
            Observations = ["Beacon to c2.example.org every 30 seconds."],
            EvidenceReferences = [$"sha256 {Sha256}"],
            RecommendedActions = ["Block 1.2.3.4 and payload.example.net."],
        };

        Assert.Empty(ThreatShareIocExtractor.Extract(finding, Evidence("8.8.8.8:443")));
    }

    [Fact]
    public void An_indicator_the_evidence_did_not_observe_is_dropped()
    {
        var finding = Finding(
            new AiIndicator { Type = "ip", Value = "6.6.6.6", Role = "malicious" },
            new AiIndicator { Type = "domain", Value = "victim.example", Role = "malicious" });

        Assert.Empty(ThreatShareIocExtractor.Extract(finding, Evidence("8.8.8.8:443")));
    }

    [Fact]
    public void Only_the_malicious_role_is_shared()
    {
        var finding = Finding(
            new AiIndicator { Type = "ip", Value = "8.8.8.8", Role = "suspicious" },
            new AiIndicator { Type = "ip", Value = "8.8.4.4", Role = "unknown" },
            new AiIndicator { Type = "ip", Value = "9.9.9.9", Role = "benign" });

        Assert.Empty(ThreatShareIocExtractor.Extract(finding, Evidence("8.8.8.8:443", "8.8.4.4:443", "9.9.9.9:443")));
    }

    [Fact]
    public void Low_severity_or_insufficient_status_proposes_nothing()
    {
        var indicator = new AiIndicator { Type = "ip", Value = "8.8.8.8", Role = "malicious" };

        Assert.Empty(ThreatShareIocExtractor.Extract(
            Finding(indicator) with { Severity = "medium" },
            Evidence("8.8.8.8:443")));

        Assert.Empty(ThreatShareIocExtractor.Extract(
            Finding(indicator) with { Status = "INSUFFICIENT_DATA", Severity = "critical" },
            Evidence("8.8.8.8:443")));
    }

    [Fact]
    public void A_private_remote_never_becomes_a_candidate()
    {
        var finding = Finding(new AiIndicator { Type = "ip", Value = "192.168.1.20", Role = "malicious" });

        Assert.Empty(ThreatShareIocExtractor.Extract(finding, Evidence("192.168.1.20:443")));
    }

    [Fact]
    public void A_value_already_blocked_from_a_public_list_is_not_shared_by_the_analyst()
    {
        var finding = Finding(
            new AiIndicator { Type = "domain", Value = "evil.example", Role = "malicious" },
            new AiIndicator { Type = "url", Value = "https://evil.example/drop", Role = "malicious" },
            new AiIndicator { Type = "ip", Value = "8.8.8.8", Role = "malicious" });
        var listDerived = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "evil.example" };

        var candidates = ThreatShareIocExtractor.Extract(
            finding,
            Evidence("evil.example:443", "8.8.8.8:443"),
            listDerived);

        var candidate = Assert.Single(candidates);
        Assert.Equal("8.8.8.8", candidate.Value);
    }

    [Fact]
    public void Unavailable_provenance_fails_closed()
    {
        var finding = Finding(
            new AiIndicator { Type = "ip", Value = "8.8.8.8", Role = "malicious" },
            new AiIndicator { Type = "domain", Value = "c2.example.org", Role = "malicious" });

        var candidates = ThreatShareIocExtractor.Extract(
            finding,
            Evidence("8.8.8.8:443", "c2.example.org:443"),
            listDerivedValues: null,
            provenanceAvailable: false);

        Assert.Empty(candidates);
    }

    [Fact]
    public void Without_the_evidence_package_nothing_is_proposed()
    {
        var finding = Finding(new AiIndicator { Type = "ip", Value = "8.8.8.8", Role = "malicious" });

        Assert.Empty(ThreatShareIocExtractor.Extract(finding, null));
    }

    private const string Sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static AiFinding Finding(params AiIndicator[] indicators) => new()
    {
        Status = "SUSPICIOUS",
        Severity = "high",
        Summary = "A remote endpoint looks malicious.",
        Indicators = indicators,
    };

    private static AiEvidencePackage Evidence(params string[] remotes) => new(
        "2",
        DateTimeOffset.UtcNow,
        "test",
        "paths-redacted",
        [],
        remotes
            .Select((remote, index) => new AiEvidenceConnection(
                $"connection-{index + 1}",
                "test.exe",
                null,
                1,
                "Tcp",
                "Outbound",
                "Established",
                "127.0.0.1:50000",
                remote,
                false,
                false,
                DateTimeOffset.UtcNow,
                "Complete"))
            .ToArray());
}
