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
        AiEvidencePackage? evidence)
    {
        ArgumentNullException.ThrowIfNull(finding);

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
                !WasObserved(indicator.Type, normalized, observed) ||
                !seen.Add(indicator.Type.Trim() + ":" + normalized))
            {
                continue;
            }

            results.Add(new ThreatShareEnqueueRequest
            {
                IndicatorType = indicator.Type.Trim().ToLowerInvariant(),
                Value = normalized,
                Reason = "malware-delivery",
                Context = "in-tool-output",
                Source = ThreatShareSource.AiAnalyst,
                Detail = "AI Analyst labelled this value malicious; Axiom observed it as a remote endpoint in the evidence it supplied.",
                ObservedUtc = finding.AnalysisTimestampUtc,
            });

            if (results.Count >= MaxCandidates)
            {
                break;
            }
        }

        return results;
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
        if (string.IsNullOrWhiteSpace(endpoint) ||
            string.Equals(endpoint, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            return;
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

        host = host.Trim().TrimEnd('.').ToLowerInvariant();
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

    private static bool WasObserved(string type, string value, ObservedHosts observed) =>
        type.Trim().ToLowerInvariant() switch
        {
            "ip" => observed.Addresses.Contains(value),
            "domain" => observed.Names.Contains(value.TrimEnd('.')),
            "url" => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                     (observed.Names.Contains(uri.Host) || observed.Addresses.Contains(uri.Host)),
            "hash" => observed.Hashes.Contains(value),
            _ => false,
        };
}
