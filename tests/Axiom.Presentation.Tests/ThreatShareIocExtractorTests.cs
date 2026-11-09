// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ai;
using Axiom.Contracts.Threat;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatShareIocExtractorTests
{
    [Fact]
    public void Suspicious_high_finding_yields_typed_candidates_and_skips_noise()
    {
        var finding = new AiFinding
        {
            Status = "SUSPICIOUS",
            Severity = "high",
            Summary = "The process fetched https://payload.example.net/drop.bin and contacted 8.8.8.8.",
            Observations =
            [
                "Beacon to c2.example.org every 30 seconds.",
                "Vendor update from microsoft.com is expected.",
                "Opened C:\\Users\\me\\report.pdf.",
            ],
            EvidenceReferences = ["sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        };

        var candidates = ThreatShareIocExtractor.Extract(finding);

        Assert.Contains(candidates, candidate => candidate.IndicatorType == "url");
        Assert.Contains(candidates, candidate => candidate.IndicatorType == "ip" && candidate.Value == "8.8.8.8");
        Assert.Contains(candidates, candidate => candidate.IndicatorType == "domain" && candidate.Value == "c2.example.org");
        Assert.Contains(candidates, candidate => candidate.IndicatorType == "hash");
        Assert.DoesNotContain(candidates, candidate => candidate.Value.Contains("microsoft.com", StringComparison.Ordinal));
        Assert.DoesNotContain(candidates, candidate => candidate.Value.EndsWith("report.pdf", StringComparison.Ordinal));
        Assert.All(candidates, candidate =>
        {
            Assert.Equal(ThreatShareSource.AiAnalyst, candidate.Source);
            Assert.Equal("in-tool-output", candidate.Context);
        });
    }

    [Fact]
    public void Low_confidence_or_benign_findings_propose_nothing()
    {
        var lowSeverity = new AiFinding
        {
            Status = "SUSPICIOUS",
            Severity = "medium",
            Summary = "Contact with suspicious.example.com.",
        };
        Assert.Empty(ThreatShareIocExtractor.Extract(lowSeverity));

        var insufficient = new AiFinding
        {
            Status = "INSUFFICIENT_DATA",
            Severity = "critical",
            Summary = "Nothing conclusive at suspicious.example.com.",
        };
        Assert.Empty(ThreatShareIocExtractor.Extract(insufficient));

        var privateAddresses = new AiFinding
        {
            Status = "SUPPORTED_ALERT",
            Severity = "critical",
            Summary = "Only local traffic 192.168.1.20 and 127.0.0.1 plus report.pdf.",
        };
        Assert.Empty(ThreatShareIocExtractor.Extract(privateAddresses));
    }
}
