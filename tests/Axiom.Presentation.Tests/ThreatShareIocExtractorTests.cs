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
            Assert.Equal(ThreatShareVocabulary.ObservedNetworkContext, candidate.Context);
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

    [Fact]
    public void Omitted_reason_defaults_to_unknown_and_below_high_confidence_is_held_local()
    {
        var finding = Finding(
            new AiIndicator { Type = "domain", Value = "c2.example.org", Role = "malicious" },
            new AiIndicator { Type = "domain", Value = "drop.example.org", Role = "malicious", Reason = "exfil-endpoint" })
            with
            {
                Confidence = "medium",
            };

        var candidates = ThreatShareIocExtractor.Extract(
            finding,
            Evidence("c2.example.org:443", "drop.example.org:443"));

        var omitted = Assert.Single(candidates, c => c.Value == "c2.example.org");
        Assert.Equal("unknown", omitted.Reason);
        Assert.Equal(ThreatSharePublicationEligibility.NeedsEvidence, omitted.PublicationEligibility);
        Assert.Equal("UNSPECIFIED_THREAT_REASON", omitted.EligibilityReasonCode);

        var mediumConfidence = Assert.Single(candidates, c => c.Value == "drop.example.org");
        Assert.Equal("exfil-endpoint", mediumConfidence.Reason);
        Assert.Equal(ThreatSharePublicationEligibility.NeedsEvidence, mediumConfidence.PublicationEligibility);
        Assert.Equal("BEHAVIOR_NEEDS_VERIFICATION", mediumConfidence.EligibilityReasonCode);
    }

    [Fact]
    public void Confirmed_process_dns_correlation_adds_a_domain_but_keeps_it_local()
    {
        var observedUtc = DateTimeOffset.UtcNow;
        var finding = new AiFinding
        {
            Status = "SUPPORTED_ALERT",
            Severity = "high",
            Confidence = "high",
            AnalysisTimestampUtc = observedUtc,
            Indicators =
            [
                new AiIndicator
                {
                    Type = "ip",
                    Value = "93.184.216.34",
                    Role = "malicious",
                    Reason = "command-and-control",
                },
            ],
        };
        var evidence = new AiEvidencePackage(
            "2",
            observedUtc,
            "test",
            "paths-redacted",
            [],
            [
                new AiEvidenceConnection(
                    "connection-1",
                    "opencode.exe",
                    null,
                    4242,
                    "Tcp",
                    "Outbound",
                    "Established",
                    "10.0.0.5:50000",
                    "93.184.216.34:443",
                    false,
                    true,
                    observedUtc,
                    "Complete"),
            ]);
        var dns = new[]
        {
            new DnsObservationRecord
            {
                QueryName = "c2-node.example.org",
                AnswerAddresses = ["93.184.216.34"],
                TtlSeconds = 300,
                ObservedUtc = observedUtc.AddSeconds(-5),
                ProcessId = 4242,
                ResolverSource = "system-resolver",
            },
        };

        var candidates = ThreatShareIocExtractor.Extract(
            finding,
            evidence,
            listDerivedValues: null,
            provenanceAvailable: true,
            dnsObservations: dns);

        var domainCandidate = Assert.Single(candidates, c => c.IndicatorType == "domain");
        Assert.Equal("c2-node.example.org", domainCandidate.Value);
        Assert.Equal("command-and-control", domainCandidate.Reason);
        Assert.Equal(ThreatShareProofGrade.Correlated, domainCandidate.ProofGrade);
        Assert.Equal(ThreatSharePublicationEligibility.NeedsEvidence, domainCandidate.PublicationEligibility);

        var mediumCorrelated = ThreatShareIocExtractor.Extract(
            finding with { Confidence = "medium" },
            evidence,
            listDerivedValues: null,
            provenanceAvailable: true,
            dnsObservations: dns);
        var mediumDomain = Assert.Single(mediumCorrelated, c => c.IndicatorType == "domain");
        Assert.Equal(ThreatSharePublicationEligibility.NeedsEvidence, mediumDomain.PublicationEligibility);
        Assert.Equal("BEHAVIOR_NEEDS_VERIFICATION", mediumDomain.EligibilityReasonCode);
    }

    [Fact]
    public void Dns_correlator_rejects_multi_domain_shared_ip_cross_process_and_unverified_doh()
    {
        var now = DateTimeOffset.UtcNow;
        var multiDomain = DnsProcessConnectionCorrelator.Correlate(
            "93.184.216.34",
            100,
            null,
            now,
            [
                new DnsObservationRecord { QueryName = "a.example.org", AnswerAddresses = ["93.184.216.34"], ObservedUtc = now.AddSeconds(-3), ProcessId = 100 },
                new DnsObservationRecord { QueryName = "b.example.org", AnswerAddresses = ["93.184.216.34"], ObservedUtc = now.AddSeconds(-2), ProcessId = 100 },
            ]);
        Assert.Equal(DnsCorrelationStatus.Ambiguous, multiDomain.Status);
        Assert.Equal("SHARED_IP_MULTIPLE_DOMAINS", multiDomain.ReasonCode);

        var unverifiedDoh = DnsProcessConnectionCorrelator.Correlate(
            "93.184.216.34",
            100,
            null,
            now,
            [
                new DnsObservationRecord { QueryName = "c.example.org", AnswerAddresses = ["93.184.216.34"], ObservedUtc = now.AddSeconds(-2), ProcessId = 100, ResolverSource = "doh-unverified" },
            ]);
        Assert.Equal(DnsCorrelationStatus.Ambiguous, unverifiedDoh.Status);

        var crossProcess = DnsProcessConnectionCorrelator.Correlate(
            "93.184.216.34",
            100,
            null,
            now,
            [
                new DnsObservationRecord { QueryName = "d.example.org", AnswerAddresses = ["93.184.216.34"], ObservedUtc = now.AddSeconds(-2), ProcessId = 999 },
            ]);
        Assert.Equal(DnsCorrelationStatus.PossibleAssociation, crossProcess.Status);

        var unavailable = DnsProcessConnectionCorrelator.Correlate("93.184.216.34", 100, null, now, []);
        Assert.Equal(DnsCorrelationStatus.Unavailable, unavailable.Status);
    }

    [Fact]
    public void Ipv6_url_indicator_matches_observed_endpoint_and_respects_list_derived_filter()
    {
        var finding = Finding(
            new AiIndicator { Type = "url", Value = "https://[2606:4700:4700::9999]", Role = "malicious" });

        var observed = ThreatShareIocExtractor.Extract(
            finding,
            Evidence("[2606:4700:4700::9999]:443"));
        var extracted = Assert.Single(observed);
        Assert.Equal("url", extracted.IndicatorType);
        Assert.Equal("https://[2606:4700:4700::9999]", extracted.Value);

        var suppressed = ThreatShareIocExtractor.Extract(
            finding,
            Evidence("[2606:4700:4700::9999]:443"),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "2606:4700:4700::9999" });
        Assert.Empty(suppressed);
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
