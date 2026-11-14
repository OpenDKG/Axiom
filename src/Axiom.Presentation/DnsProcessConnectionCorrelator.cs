// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

public enum DnsCorrelationStatus
{
    Unavailable = 0,
    PossibleAssociation = 1,
    Ambiguous = 2,
    ConfirmedAssociation = 3,
}

public sealed record DnsObservationRecord
{
    public required string QueryName { get; init; }

    public IReadOnlyList<string> AnswerAddresses { get; init; } = [];

    public IReadOnlyList<string> Cnames { get; init; } = [];

    public int TtlSeconds { get; init; } = 300;

    public required DateTimeOffset ObservedUtc { get; init; }

    public int ProcessId { get; init; }

    public int? ParentProcessId { get; init; }

    /// <summary>Origin of the DNS answer (for example "system-resolver", "doh-unverified", "proxy-unknown").</summary>
    public string ResolverSource { get; init; } = "system-resolver";
}

public sealed record DnsCorrelationResult(
    DnsCorrelationStatus Status,
    string? CanonicalDomain,
    string ReasonCode,
    string Explanation);

/// <summary>
/// Correlates a socket connection back to an observed local DNS resolution using process lineage,
/// answer IP records, CNAME/query names, and TTL windows. Never guesses across unverified DoH,
/// unknown proxies, reverse DNS, or shared multi-domain IPs.
/// </summary>
public static class DnsProcessConnectionCorrelator
{
    private const int MinTtlWindowSeconds = 60;
    private const int MaxTtlWindowSeconds = 86_400;
    private static readonly TimeSpan FutureSkewTolerance = TimeSpan.FromSeconds(2);

    public static DnsCorrelationResult Correlate(
        string? remoteAddress,
        int processId,
        int? parentProcessId,
        DateTimeOffset connectionObservedUtc,
        IReadOnlyList<DnsObservationRecord>? observations)
    {
        var normalizedIp = NormalizeIp(remoteAddress);
        if (normalizedIp is null || observations is null || observations.Count == 0)
        {
            return new(
                DnsCorrelationStatus.Unavailable,
                null,
                "NO_MATCHING_DNS_OBSERVATION",
                "No DNS observation records are available for this connection.");
        }

        var inWindow = observations
            .Where(record => IsMatchingAnswer(record, normalizedIp, connectionObservedUtc))
            .ToList();

        if (inWindow.Count == 0)
        {
            return new(
                DnsCorrelationStatus.Unavailable,
                null,
                "NO_MATCHING_DNS_OBSERVATION",
                "No in-TTL DNS answer matched the remote IP address.");
        }

        var trusted = inWindow
            .Where(record => !IsUnverifiedResolver(record.ResolverSource))
            .ToList();

        if (trusted.Count == 0)
        {
            return new(
                DnsCorrelationStatus.Ambiguous,
                null,
                "UNATTRIBUTED_RESOLVER_SOURCE",
                "Only unverified DoH or proxy DNS records exist; host attribution cannot be proven.");
        }

        var lineageMatches = trusted
            .Where(record => MatchesProcessLineage(record, processId, parentProcessId))
            .ToList();

        if (lineageMatches.Count == 0)
        {
            var candidateDomain = ExtractDistinctCanonicalDomains(trusted).FirstOrDefault();
            return new(
                DnsCorrelationStatus.PossibleAssociation,
                candidateDomain,
                "CROSS_PROCESS_OR_CACHE_ONLY",
                "DNS answer came from a different process or shared cache, not the connecting process lineage.");
        }

        var lineageDomains = ExtractDistinctCanonicalDomains(lineageMatches);
        if (lineageDomains.Count > 1)
        {
            return new(
                DnsCorrelationStatus.Ambiguous,
                null,
                "SHARED_IP_MULTIPLE_DOMAINS",
                $"Multiple queried domains resolved to {normalizedIp} within the TTL window.");
        }

        if (lineageDomains.Count == 0)
        {
            return new(
                DnsCorrelationStatus.Ambiguous,
                null,
                "INVALID_QUERY_DOMAIN",
                "Matched DNS observation did not carry a valid canonical domain.");
        }

        return new(
            DnsCorrelationStatus.ConfirmedAssociation,
            lineageDomains[0],
            "CONFIRMED_PROCESS_DNS_TTL",
            "Process-attributed DNS answer matched the remote IP within the valid TTL window.");
    }

    private static bool IsMatchingAnswer(
        DnsObservationRecord record,
        string normalizedIp,
        DateTimeOffset connectionObservedUtc)
    {
        if (record.ObservedUtc > connectionObservedUtc + FutureSkewTolerance)
        {
            return false;
        }

        var ttlSeconds = Math.Clamp(record.TtlSeconds, MinTtlWindowSeconds, MaxTtlWindowSeconds);
        if (connectionObservedUtc > record.ObservedUtc + TimeSpan.FromSeconds(ttlSeconds))
        {
            return false;
        }

        return record.AnswerAddresses.Any(answer =>
            string.Equals(NormalizeIp(answer), normalizedIp, StringComparison.OrdinalIgnoreCase));
    }

    private static bool MatchesProcessLineage(
        DnsObservationRecord record,
        int processId,
        int? parentProcessId)
    {
        if (processId <= 0 && parentProcessId is null or <= 0)
        {
            return false;
        }

        if (record.ProcessId <= 0)
        {
            return false;
        }

        return (processId > 0 && record.ProcessId == processId) ||
               (parentProcessId is > 0 &&
                (record.ProcessId == parentProcessId.Value ||
                 record.ParentProcessId == parentProcessId.Value));
    }

    private static bool IsUnverifiedResolver(string? source)
    {
        var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
        return normalized is "doh-unverified" or "proxy-unknown";
    }

    private static List<string> ExtractDistinctCanonicalDomains(IEnumerable<DnsObservationRecord> records)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in records)
        {
            if (ThreatShareVocabulary.Normalize("domain", record.QueryName) is { } canonical)
            {
                domains.Add(canonical);
            }
        }

        return domains.ToList();
    }

    private static string? NormalizeIp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var trimmed = raw.Trim().Trim('[', ']');
        if (!IPAddress.TryParse(trimmed, out var address))
        {
            return null;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
            address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.ToString().ToLowerInvariant();
    }
}
