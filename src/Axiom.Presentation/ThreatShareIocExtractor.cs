// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

/// <summary>
/// Turns the structured indicators of an AI finding into share candidates. Prose is never scanned:
/// the model may label a value, but Axiom only proposes values it observed itself as a remote
/// endpoint. Nothing is sent here; the candidates land in the Agents-page review list, and the user
/// decides whether to share each one.
/// </summary>
public static class ThreatShareIocExtractor
{
    private const int MaxCandidates = 5;

    public static IReadOnlyList<ThreatShareEnqueueRequest> Extract(
        AiFinding finding,
        AiEvidencePackage? evidence,
        IReadOnlySet<string>? listDerivedValues = null,
        bool provenanceAvailable = true,
        IReadOnlyList<DnsObservationRecord>? dnsObservations = null)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (!provenanceAvailable)
        {
            // Without the local block history Axiom cannot rule out that this value came from a
            // public list. Fail closed instead of presenting it as independent evidence.
            return [];
        }

        var status = (finding.Status ?? string.Empty).Trim().ToUpperInvariant();
        var severity = (finding.Severity ?? string.Empty).Trim().ToLowerInvariant();
        if (status is not ("SUSPICIOUS" or "SUPPORTED_ALERT") ||
            severity is not ("high" or "critical") ||
            evidence is null)
        {
            return [];
        }

        var observed = CollectObservedHosts(evidence);
        var results = new List<ThreatShareEnqueueRequest>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var indicator in finding.Indicators ?? [])
        {
            if (!string.Equals(
                    (indicator.Role ?? string.Empty).Trim(),
                    "malicious",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (ThreatShareVocabulary.Normalize(indicator.Type, indicator.Value) is not { } normalized ||
                WasListDerived(indicator.Type, normalized, listDerivedValues) ||
                !WasObserved(indicator.Type, normalized, observed))
            {
                continue;
            }

            var type = indicator.Type.Trim().ToLowerInvariant();
            var reason = ResolveReason(indicator);
            var normalizedSeverity = ThreatShareVocabulary.NormalizeSeverity(finding.Severity);

            if (seen.Add(type + ":" + normalized))
            {
                results.Add(BuildRequest(
                    type,
                    normalized,
                    reason,
                    normalizedSeverity,
                    finding,
                    ThreatShareEvidenceClass.HeuristicOrAiSuspected,
                    ThreatShareProofGrade.Observed,
                    "AI Analyst labelled this value malicious; Axiom observed it as a remote endpoint in the evidence it supplied."));

                if (results.Count >= MaxCandidates)
                {
                    break;
                }
            }

            if (type == "ip" && dnsObservations is { Count: > 0 } && results.Count < MaxCandidates)
            {
                var correlatedDomain = TryCorrelateDomain(normalized, evidence, dnsObservations);
                if (correlatedDomain is not null &&
                    ThreatShareVocabulary.Normalize("domain", correlatedDomain) is { } canonicalDomain &&
                    !WasListDerived("domain", canonicalDomain, listDerivedValues) &&
                    seen.Add("domain:" + canonicalDomain))
                {
                    results.Add(BuildRequest(
                        "domain",
                        canonicalDomain,
                        reason,
                        normalizedSeverity,
                        finding,
                        ThreatShareEvidenceClass.HeuristicOrAiSuspected,
                        ThreatShareProofGrade.Correlated,
                        $"AI Analyst labelled {normalized} malicious; Axiom observed it and correlated the process DNS query to {canonicalDomain}."));

                    if (results.Count >= MaxCandidates)
                    {
                        break;
                    }
                }
            }
        }

        return results;
    }

    private static ThreatShareEnqueueRequest BuildRequest(
        string type,
        string value,
        string reason,
        string severity,
        AiFinding finding,
        ThreatShareEvidenceClass evidenceClass,
        ThreatShareProofGrade proofGrade,
        string detail)
    {
        var assessment = ThreatShareVocabulary.EvaluatePublicationEligibility(
            type,
            value,
            reason,
            evidenceClass,
            proofGrade,
            listDerived: false);

        return new ThreatShareEnqueueRequest
        {
            IndicatorType = type,
            Value = value,
            Reason = reason,
            Context = ThreatShareVocabulary.ObservedNetworkContext,
            Source = ThreatShareSource.AiAnalyst,
            Detail = detail,
            ObservedUtc = finding.AnalysisTimestampUtc,
            Severity = severity,
            EvidenceClass = evidenceClass,
            ProofGrade = proofGrade,
            PublicationEligibility = assessment.Eligibility,
            EligibilityReasonCode = assessment.ReasonCode,
            EligibilityExplanation = assessment.Explanation,
        };
    }

    private static string ResolveReason(AiIndicator indicator)
    {
        var candidate = (indicator.Reason ?? string.Empty).Trim().ToLowerInvariant();
        return ThreatShareVocabulary.IsPublishableReason(candidate) ? candidate : "unknown";
    }

    private static string? TryCorrelateDomain(
        string normalizedIp,
        AiEvidencePackage evidence,
        IReadOnlyList<DnsObservationRecord> dnsObservations)
    {
        foreach (var connection in evidence.Connections)
        {
            var host = ExtractHost(connection.RemoteEndpoint);
            if (!IPAddress.TryParse(host, out var address))
            {
                continue;
            }

            var canonical = (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address)
                .ToString()
                .ToLowerInvariant();
            if (!string.Equals(canonical, normalizedIp, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var correlation = DnsProcessConnectionCorrelator.Correlate(
                canonical,
                connection.ProcessId,
                connection.ParentProcessId,
                connection.FirstObservedUtc,
                dnsObservations);

            if (correlation.Status == DnsCorrelationStatus.ConfirmedAssociation &&
                !string.IsNullOrWhiteSpace(correlation.CanonicalDomain))
            {
                return correlation.CanonicalDomain;
            }
        }

        return null;
    }

    private sealed record ObservedHosts(
        HashSet<string> Addresses,
        HashSet<string> Names,
        HashSet<string> Hashes);

    private static ObservedHosts CollectObservedHosts(AiEvidencePackage evidence)
    {
        var observed = new ObservedHosts(
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        foreach (var connection in evidence.Connections)
        {
            AddEndpoint(observed, connection.RemoteEndpoint);
            foreach (var remote in connection.BaselineTypicalRemotes)
            {
                AddEndpoint(observed, remote);
            }
        }

        // The evidence package does not contain a file hash Axiom computed yet, so a hash the model
        // names can never pass the observed-value gate above. Add hashes here only when the evidence
        // itself starts carrying them.
        return observed;
    }

    private static void AddEndpoint(ObservedHosts observed, string endpoint)
    {
        var host = ExtractHost(endpoint);
        if (host.Length == 0)
        {
            return;
        }

        if (IPAddress.TryParse(host, out var address))
        {
            observed.Addresses.Add(address.ToString());
            if (address.IsIPv4MappedToIPv6)
            {
                observed.Addresses.Add(address.MapToIPv4().ToString());
            }

            return;
        }

        observed.Names.Add(host);
    }

    private static string ExtractHost(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint) ||
            string.Equals(endpoint, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        var host = endpoint.Trim();
        if (host.StartsWith('['))
        {
            var close = host.IndexOf(']');
            if (close > 0)
            {
                host = host[1..close];
            }
        }
        else
        {
            var colon = host.LastIndexOf(':');
            if (colon > 0 && host.IndexOf(':') == colon &&
                int.TryParse(host[(colon + 1)..], out _))
            {
                host = host[..colon];
            }
        }

        return host.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static bool WasObserved(string type, string value, ObservedHosts observed) =>
        type.Trim().ToLowerInvariant() switch
        {
            "ip" => observed.Addresses.Contains(value),
            "domain" => observed.Names.Contains(value.TrimEnd('.')),
            "url" => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                     ExtractUriHost(uri) is { Length: > 0 } host &&
                     (observed.Names.Contains(host) || observed.Addresses.Contains(host)),
            "hash" => observed.Hashes.Contains(value),
            _ => false,
        };

    /// <summary>
    /// Suppress a value that local public-list blocks already contain. The model observing the same
    /// endpoint again must not turn a list match into a second, supposedly independent sighting.
    /// </summary>
    private static bool WasListDerived(
        string type,
        string value,
        IReadOnlySet<string>? listDerivedValues)
    {
        if (listDerivedValues is null || listDerivedValues.Count == 0)
        {
            return false;
        }

        return type.Trim().ToLowerInvariant() switch
        {
            "domain" or "ip" or "hash" => listDerivedValues.Contains(value.TrimEnd('.')),
            "url" => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                     ExtractUriHost(uri) is { Length: > 0 } host &&
                     listDerivedValues.Contains(host),
            _ => false,
        };
    }

    private static string ExtractUriHost(Uri uri) =>
        uri.IdnHost.Trim('[', ']').TrimEnd('.');
}
