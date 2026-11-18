// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Threat;

/// <summary>Where Axiom observed the indicator.</summary>
public enum ThreatShareSource
{
    /// <summary>A Privacy Shield malware-list block attributed to an agent process.</summary>
    PrivacyShield = 0,

    /// <summary>An IOC the AI Analyst reported from agent evidence.</summary>
    AiAnalyst = 1,
}

/// <summary>Local evidence provenance class; never silently upgraded in storage.</summary>
public enum ThreatShareEvidenceClass
{
    LocalObservation = 0,
    PublicFeedMatch = 1,
    HeuristicOrAiSuspected = 2,
    ReproducibleAttackArtifact = 3,
    CuratorConfirmed = 4,
}

/// <summary>Validation strength recorded alongside a candidate.</summary>
public enum ThreatShareProofGrade
{
    Observed = 0,
    Correlated = 1,
    Reproduced = 2,
    IndependentlyConfirmed = 3,
}

/// <summary>Conservative local publication gate before any Blackbox submission.</summary>
public enum ThreatSharePublicationEligibility
{
    LocalOnly = 0,
    NeedsEvidence = 1,
    NeedsOperatorReview = 2,
    EligibleToSubmit = 3,
}

/// <summary>Read-only local graph novelty status; curators exclusively award novelty.</summary>
public enum ThreatShareNoveltyStatus
{
    Unknown = 0,
    PotentiallyNewLocalOnly = 1,
    PreviouslyReportedCommunity = 2,
    KnownVerified = 3,
    Disputed = 4,
    Revoked = 5,
}

public sealed record ThreatShareEligibilityAssessment(
    ThreatSharePublicationEligibility Eligibility,
    string ReasonCode,
    string Explanation);

/// <summary>One indicator Axiom proposes to share, before it is signed by Blackbox.</summary>
public sealed record ThreatShareEnqueueRequest
{
    /// <summary>Blackbox IOC type: domain, url, ip or hash.</summary>
    public required string IndicatorType { get; init; }

    public required string Value { get; init; }

    /// <summary>One of <see cref="ThreatShareVocabulary.Reasons"/>.</summary>
    public required string Reason { get; init; }

    /// <summary>Where it was seen; one of <see cref="ThreatShareVocabulary.Contexts"/>.</summary>
    public required string Context { get; init; }

    public required ThreatShareSource Source { get; init; }

    /// <summary>Human-readable note shown in the preview list; never sent as free text.</summary>
    public string Detail { get; init; } = string.Empty;

    public DateTimeOffset ObservedUtc { get; init; } = DateTimeOffset.UtcNow;

    public string Severity { get; init; } = "high";

    public ThreatShareEvidenceClass EvidenceClass { get; init; } = ThreatShareEvidenceClass.HeuristicOrAiSuspected;

    public ThreatShareProofGrade ProofGrade { get; init; } = ThreatShareProofGrade.Observed;

    public ThreatSharePublicationEligibility PublicationEligibility { get; init; } = ThreatSharePublicationEligibility.NeedsOperatorReview;

    public ThreatShareNoveltyStatus NoveltyStatus { get; init; } = ThreatShareNoveltyStatus.Unknown;

    public string EligibilityReasonCode { get; init; } = string.Empty;

    public string EligibilityExplanation { get; init; } = string.Empty;
}

/// <summary>A validated, deduplicated candidate held in the local share queue.</summary>
public sealed record ThreatShareCandidate
{
    /// <summary>Stable identifier: <c>ioc:{type}:{value}</c>.</summary>
    public required string Id { get; init; }

    public required string IndicatorType { get; init; }

    public required string Value { get; init; }

    public required string Reason { get; init; }

    public required string Context { get; init; }

    public required ThreatShareSource Source { get; init; }

    public string Detail { get; init; } = string.Empty;

    public DateTimeOffset ObservedUtc { get; init; }

    public string Severity { get; init; } = "high";

    public ThreatShareEvidenceClass EvidenceClass { get; init; } = ThreatShareEvidenceClass.HeuristicOrAiSuspected;

    public ThreatShareProofGrade ProofGrade { get; init; } = ThreatShareProofGrade.Observed;

    public ThreatSharePublicationEligibility PublicationEligibility { get; init; } = ThreatSharePublicationEligibility.NeedsOperatorReview;

    public ThreatShareNoveltyStatus NoveltyStatus { get; init; } = ThreatShareNoveltyStatus.Unknown;

    public string EligibilityReasonCode { get; init; } = string.Empty;

    public string EligibilityExplanation { get; init; } = string.Empty;

    public string TypeLabel => IndicatorType;

    public string SourceLabel => Source switch
    {
        ThreatShareSource.PrivacyShield => "Privacy Shield",
        ThreatShareSource.AiAnalyst => "AI Analyst",
        _ => "Axiom",
    };

    public bool CanPublishToCommunity =>
        (PublicationEligibility is ThreatSharePublicationEligibility.NeedsOperatorReview or
            ThreatSharePublicationEligibility.EligibleToSubmit) &&
        NoveltyStatus is not (ThreatShareNoveltyStatus.KnownVerified or ThreatShareNoveltyStatus.Disputed or
            ThreatShareNoveltyStatus.Revoked) &&
        ThreatShareVocabulary.ReportableContexts.Contains(Context, StringComparer.Ordinal) &&
        string.Equals(ThreatShareVocabulary.Normalize(IndicatorType, Value), Value, StringComparison.Ordinal) &&
        string.Equals(Id, ThreatShareVocabulary.BuildId(IndicatorType, Value), StringComparison.Ordinal) &&
        ThreatShareVocabulary.EvaluatePublicationEligibility(
            IndicatorType, Value, Reason, EvidenceClass, ProofGrade).Eligibility >=
                ThreatSharePublicationEligibility.NeedsOperatorReview;

    public string NoveltyLabel => NoveltyStatus switch
    {
        ThreatShareNoveltyStatus.PotentiallyNewLocalOnly => "Potentially new (local graph only)",
        ThreatShareNoveltyStatus.PreviouslyReportedCommunity => "Previously reported (community)",
        ThreatShareNoveltyStatus.KnownVerified => "Known (verified)",
        ThreatShareNoveltyStatus.Disputed => "Disputed",
        ThreatShareNoveltyStatus.Revoked => "Revoked",
        _ => "Unknown",
    };

    public string PublicPayloadPreview =>
        $"type=ioc · ioc_type={IndicatorType} · value={Value} · context={Context} · severity={ThreatShareVocabulary.NormalizeSeverity(Severity)} " +
        $"(local reason: {Reason}; CC0 1.0 replicated statement)";
}

/// <summary>Queue state of one candidate.</summary>
public enum ThreatShareState
{
    Pending = 0,
    Submitted = 1,
    Rejected = 2,
    Dismissed = 3,

    /// <summary>A transient reporter failure. The candidate stays in the queue with a retry time.</summary>
    Deferred = 4,

    /// <summary>
    /// The reporter ran but its outcome is unknown (for example a timeout after start). The value
    /// may already be published, so it is never retried automatically.
    /// </summary>
    Unverified = 5,

    /// <summary>Operator requested retraction of their own report; replicas may persist.</summary>
    Retracted = 6,
}

public sealed record ThreatShareItem(
    ThreatShareCandidate Candidate,
    ThreatShareState State,
    string Outcome,
    DateTimeOffset? AttemptedUtc)
{
    /// <summary>Number of reporter attempts recorded for this candidate.</summary>
    public int Attempts { get; init; }

    /// <summary>Earliest time a deferred retry should be attempted.</summary>
    public DateTimeOffset? NextAttemptUtc { get; init; }

    /// <summary>
    /// Stable key for this candidate's submission attempts. It is created on the first attempt and
    /// reused on a manual retry so an ambiguous outcome stays traceable and explainable.
    /// </summary>
    public string SubmissionKey { get; init; } = string.Empty;

    /// <summary>Button label: an ambiguous item needs a deliberate retry; submitted items can be retracted.</summary>
    public string ActionLabel => State switch
    {
        ThreatShareState.Unverified => "Retry",
        ThreatShareState.Submitted => "Retract",
        _ => "Share",
    };

    public string StateLabel => State switch
    {
        ThreatShareState.Submitted => "shared",
        ThreatShareState.Rejected => "rejected",
        ThreatShareState.Dismissed => "dismissed",
        ThreatShareState.Deferred => "deferred",
        ThreatShareState.Unverified => "awaiting confirmation",
        ThreatShareState.Retracted => "retracted",
        _ => "pending review",
    };

    public string StateDetail => State switch
    {
        ThreatShareState.Deferred =>
            (NextAttemptUtc is { } next ? $"retry after {next.ToLocalTime():HH:mm}" : "retry later") +
            (string.IsNullOrWhiteSpace(Outcome) ? string.Empty : $" · {Outcome}"),
        ThreatShareState.Rejected => Outcome,
        ThreatShareState.Unverified =>
            "the previous attempt may have published; confirm before retrying" +
            (string.IsNullOrWhiteSpace(Outcome) ? string.Empty : " - " + Outcome),
        ThreatShareState.Retracted =>
            string.IsNullOrWhiteSpace(Outcome)
                ? "retraction submitted; existing CC0 replicas may persist"
                : Outcome,
        ThreatShareState.Pending when !Candidate.CanPublishToCommunity &&
                                      !string.IsNullOrWhiteSpace(Candidate.EligibilityExplanation) =>
            Candidate.EligibilityExplanation,
        _ => string.Empty,
    };

    public bool HasStateDetail => StateDetail.Length > 0;
}

/// <summary>The preview list and counters the Agents page shows.</summary>
public sealed record ThreatShareQueueStatus
{
    public required int Pending { get; init; }

    /// <summary>Transiently failed candidates that stay queued for a later retry.</summary>
    public int Deferred { get; init; }

    /// <summary>Ambiguous attempts that need explicit confirmation before any retry.</summary>
    public int Unverified { get; init; }

    public required int Submitted { get; init; }

    public required int TodaySubmitted { get; init; }

    public int DailyLimit { get; init; } = ThreatShareVocabulary.MaxDailySubmissions;

    public string Detail { get; init; } = string.Empty;

    public IReadOnlyList<ThreatShareItem> Items { get; init; } = [];
}

public sealed record ThreatShareDismissRequest
{
    public required string Id { get; init; }
}

/// <summary>Recorded by the desktop after it ran the Blackbox CLI in the user's own session.</summary>
public sealed record ThreatShareRecordRequest
{
    public required string Id { get; init; }

    public required bool Submitted { get; init; }

    /// <summary>True for a transient failure that should stay queued instead of being rejected.</summary>
    public bool Deferred { get; init; }

    /// <summary>True when the reporter ran but the outcome is unknown; never auto-retried.</summary>
    public bool Ambiguous { get; init; }

    /// <summary>True when the operator requested retraction of their own previously shared report.</summary>
    public bool Retracted { get; init; }

    public string Outcome { get; init; } = string.Empty;
}

public sealed record ThreatShareSubmitResult
{
    public required bool Ok { get; init; }

    public required string Detail { get; init; }

    public required ThreatShareQueueStatus Status { get; init; }
}

/// <summary>
/// The closed vocabulary Blackbox's community schema accepts. Axiom validates locally first so a
/// malformed candidate never reaches the CLI, and only honest contexts are offered.
/// </summary>
public static class ThreatShareVocabulary
{
    public const int MaxDailySubmissions = 100;

    public const int MaxQueueItems = 200;

    public static IReadOnlyList<string> IndicatorTypes { get; } = ["domain", "url", "ip", "hash"];

    /// <summary>Closed publishable Blackbox IOC reason codes.</summary>
    public static IReadOnlyList<string> PublishableReasons { get; } =
    [
        "phishing",
        "malware-delivery",
        "command-and-control",
        "credential-harvest",
        "exfil-endpoint",
        "scam",
        "injection-host",
    ];

    /// <summary>Closed reason codes accepted in Axiom's local queue (including local-only "unknown").</summary>
    public static IReadOnlyList<string> Reasons { get; } =
    [
        "phishing",
        "malware-delivery",
        "command-and-control",
        "credential-harvest",
        "exfil-endpoint",
        "scam",
        "injection-host",
        "unknown",
    ];

    public static IReadOnlyList<string> Severities { get; } = ["low", "medium", "high", "critical"];

    /// <summary>
    /// Contexts accepted by Blackbox for an independently supported observation.
    /// </summary>
    public static IReadOnlyList<string> ReportableContexts { get; } = ["fetched-by-tool", "in-tool-output"];

    public const string ObservedNetworkContext = "observed-network-endpoint";

    public static IReadOnlyList<string> Contexts { get; } = [.. ReportableContexts, ObservedNetworkContext];

    /// <summary>File-like "TLDs" that appear in free text but are never shareable domains.</summary>
    private static readonly HashSet<string> NonDomainTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "log", "json", "txt", "xml", "csv", "md", "ps1", "bat", "cmd", "msi",
        "tmp", "dat", "db", "sqlite", "pem", "key", "crt", "ini", "yaml", "yml", "zip", "gz",
        "pdf", "docx", "xlsx", "png", "jpg", "html", "lnk",
    };

    private static readonly HashSet<string> LocalDomainTlds =
        new(["local", "localhost", "internal", "intranet", "lan", "home", "corp"], StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> KnownPublicResolvers = new(StringComparer.OrdinalIgnoreCase)
    {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe",
        "dns.google", "one.one.one.one", "dns.quad9.net",
    };

    private static readonly HashSet<string> SharedHostingApexes = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.io", "raw.githubusercontent.com", "githubusercontent.com",
        "amazonaws.com", "pages.dev", "vercel.app", "netlify.app",
        "workers.dev", "herokuapp.com", "firebaseapp.com", "web.app",
        "blogspot.com", "wordpress.com", "azurewebsites.net", "cloudfront.net",
    };

    private static readonly (string Network, int PrefixBits)[] SharedInfraIpv4Cidrs =
    [
        ("104.16.0.0", 12),
        ("172.64.0.0", 13),
        ("162.158.0.0", 15),
        ("103.21.244.0", 22),
        ("198.41.128.0", 17),
        ("151.101.0.0", 16),
        ("185.199.108.0", 22),
        ("13.32.0.0", 15),
    ];

    public static bool IsSupported(string indicatorType, string reason, string context) =>
        IndicatorTypes.Contains(indicatorType, StringComparer.OrdinalIgnoreCase) &&
        Reasons.Contains(reason, StringComparer.OrdinalIgnoreCase) &&
        Contexts.Contains(context, StringComparer.OrdinalIgnoreCase);

    public static bool IsPublishableReason(string? reason) =>
        !string.IsNullOrWhiteSpace(reason) &&
        PublishableReasons.Contains(reason.Trim(), StringComparer.OrdinalIgnoreCase);

    public static string NormalizeSeverity(string? severity)
    {
        var normalized = (severity ?? string.Empty).Trim().ToLowerInvariant();
        return Severities.Contains(normalized, StringComparer.Ordinal) ? normalized : "high";
    }

    public static ThreatShareEligibilityAssessment EvaluatePublicationEligibility(
        string indicatorType,
        string normalizedValue,
        string reason,
        ThreatShareEvidenceClass evidenceClass,
        ThreatShareProofGrade proofGrade,
        bool listDerived = false)
    {
        if (listDerived || evidenceClass is ThreatShareEvidenceClass.LocalObservation or ThreatShareEvidenceClass.PublicFeedMatch)
        {
            return new(
                ThreatSharePublicationEligibility.LocalOnly,
                "PUBLIC_FEED_OR_LOCAL_ONLY",
                "Local observation or public-list match stays on this machine and is never proposed as independent corroboration.");
        }

        var type = (indicatorType ?? string.Empty).Trim().ToLowerInvariant();
        var targetHost = type == "url" && Uri.TryCreate(normalizedValue, UriKind.Absolute, out var uri)
            ? uri.IdnHost.Trim('[', ']')
            : normalizedValue.Trim('[', ']');

        if (KnownPublicResolvers.Contains(normalizedValue) || KnownPublicResolvers.Contains(targetHost))
        {
            return new(
                ThreatSharePublicationEligibility.LocalOnly,
                "NEVER_FLAG_RESOLVER",
                "Known public DNS resolver kept local-only to avoid curator never-flag rejection.");
        }

        if ((type is "domain" or "url") && SharedHostingApexes.Contains(targetHost))
        {
            return new(
                ThreatSharePublicationEligibility.NeedsEvidence,
                "SHARED_HOSTING_APEX",
                "Shared-hosting apex affects multiple tenants; submit only a specific malicious subdomain or URL with evidence.");
        }

        if (type == "ip" && System.Net.IPAddress.TryParse(targetHost, out var address) && IsSharedCloudOrCdnIp(address))
        {
            return new(
                ThreatSharePublicationEligibility.NeedsEvidence,
                "NEVER_PROMOTE_SHARED_IP",
                "Bare multi-tenant CDN/Cloud IP is kept local; correlate to a specific malicious domain before sharing.");
        }

        if (!IsPublishableReason(reason))
        {
            return new(
                ThreatSharePublicationEligibility.NeedsEvidence,
                "UNSPECIFIED_THREAT_REASON",
                "Threat reason is 'unknown'; classify with evidence-backed behavior before publishing.");
        }

        if (evidenceClass is not (ThreatShareEvidenceClass.ReproducibleAttackArtifact or
                ThreatShareEvidenceClass.CuratorConfirmed) ||
            proofGrade is not (ThreatShareProofGrade.Reproduced or ThreatShareProofGrade.IndependentlyConfirmed))
        {
            return new(
                ThreatSharePublicationEligibility.NeedsEvidence,
                "BEHAVIOR_NEEDS_VERIFICATION",
                "An observed endpoint or AI suspicion stays local until there is reproducible evidence of malicious behavior or independent confirmation.");
        }

        return new(
            ThreatSharePublicationEligibility.NeedsOperatorReview,
            "READY_FOR_OPERATOR_REVIEW",
            "Ready for explicit operator review; Blackbox curators exclusively determine acceptance and novelty.");
    }

    private static bool IsSharedCloudOrCdnIp(System.Net.IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
            address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        return SharedInfraIpv4Cidrs.Any(cidr => InNetwork(address, cidr.Network, cidr.PrefixBits));
    }

    /// <summary>Builds the stable queue id and the value Blackbox hashes, or null when invalid.</summary>
    public static string? Normalize(string indicatorType, string value, bool allowUrlPath = false)
    {
        var type = (indicatorType ?? string.Empty).Trim().ToLowerInvariant();
        var raw = (value ?? string.Empty).Trim();
        if (raw.Length == 0 || raw.Length > 2_048 || !IndicatorTypes.Contains(type))
        {
            return null;
        }

        switch (type)
        {
            case "domain":
                raw = raw.TrimEnd('.').ToLowerInvariant();
                if (!IsShareableHost(raw) || System.Net.IPAddress.TryParse(raw, out _))
                {
                    return null;
                }

                return raw;
            case "url":
                if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
                    (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
                    !IsShareableHost(uri.IdnHost))
                {
                    return null;
                }

                // Scheme, host, non-default port and path only: credentials, query strings and
                // fragments can contain tokens or presigned secrets and never leave the machine.
                // A path is not shared unless the caller explicitly opts in; paths can contain
                // account, document or session identifiers.
                if (!allowUrlPath && uri.AbsolutePath is not ("" or "/"))
                {
                    return null;
                }

                var hostForUrl = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
                if (hostForUrl.Contains(':', StringComparison.Ordinal) &&
                    !hostForUrl.StartsWith('['))
                {
                    hostForUrl = "[" + hostForUrl + "]";
                }

                var port = uri.IsDefaultPort ? string.Empty : ":" + uri.Port;
                var path = allowUrlPath ? uri.AbsolutePath : string.Empty;
                var normalizedUrl = $"{uri.Scheme}://{hostForUrl}{port}{path}"
                    .TrimEnd('/');
                return normalizedUrl.Length is > 0 and <= 2_048 ? normalizedUrl : null;
            case "ip":
                if (!System.Net.IPAddress.TryParse(raw.Trim('[', ']'), out var address))
                {
                    return null;
                }

                if (IsNonPublic(address))
                {
                    return null;
                }

                return address.ToString().ToLowerInvariant();
            case "hash":
                raw = raw.ToLowerInvariant();
                return raw.Length is 32 or 40 or 64 or 128 &&
                       raw.All(character => char.IsAsciiHexDigit(character))
                    ? raw
                    : null;
            default:
                return null;
        }
    }

    public static string BuildId(string indicatorType, string normalizedValue) =>
        $"ioc:{indicatorType.ToLowerInvariant()}:{normalizedValue}";

    /// <summary>Loopback, link-local, private, documentation, benchmarking and multicast ranges are
    /// not shareable indicators. IPv4-mapped IPv6 is checked as IPv4.</summary>
    private static bool IsNonPublic(System.Net.IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
            address.IsIPv4MappedToIPv6)
        {
            return IsNonPublic(address.MapToIPv4());
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (System.Net.IPAddress.IsLoopback(address) ||
                address.Equals(System.Net.IPAddress.IPv6Any) ||
                address.IsIPv6LinkLocal ||
                address.IsIPv6SiteLocal ||
                address.IsIPv6UniqueLocal ||
                address.IsIPv6Multicast)
            {
                return true;
            }

            return InNetwork(address, "64:ff9b::", 96) ||        // IPv4/IPv6 translation
                   InNetwork(address, "64:ff9b:1::", 48) ||      // local-use translation
                   InNetwork(address, "100::", 64) ||            // discard-only
                   InNetwork(address, "2001::", 23) ||           // IETF protocol assignments
                   InNetwork(address, "2001:db8::", 32) ||       // documentation
                   InNetwork(address, "2002::", 16) ||           // 6to4
                   InNetwork(address, "3fff::", 20) ||           // documentation
                   InNetwork(address, "5f00::", 16);             // segment-routing SIDs
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 0 ||                                   // this network
               bytes[0] == 10 ||                                  // private
               (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) || // CGNAT
               bytes[0] == 127 ||                                 // loopback
               (bytes[0] == 169 && bytes[1] == 254) ||            // link-local
               (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || // private
               (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0) || // IETF protocol assignments
               (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2) || // TEST-NET-1
               (bytes[0] == 192 && bytes[1] == 31 && bytes[2] == 196) || // AS112-v4
               (bytes[0] == 192 && bytes[1] == 52 && bytes[2] == 193) || // AMT
               (bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99) || // 6to4 relay anycast
               (bytes[0] == 192 && bytes[1] == 168) ||            // private
               (bytes[0] == 192 && bytes[1] == 175 && bytes[2] == 48) || // AS112 direct delegation
               (bytes[0] == 198 && bytes[1] is 18 or 19) ||       // benchmarking
               (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) || // TEST-NET-2
               (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) || // TEST-NET-3
               bytes[0] >= 224;                                  // multicast, reserved, broadcast
    }

    /// <summary>A URL host must be a public IP or a dotted public name; single-label and
    /// <c>.local</c> names are private by definition.</summary>
    private static bool IsShareableHost(string host)
    {
        host = (host ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        if (host.Length is 0 or > 253 ||
            host is "localhost" or "local" ||
            host.EndsWith(".localhost", StringComparison.Ordinal) ||
            host.EndsWith(".local", StringComparison.Ordinal) ||
            host.Any(character => char.IsWhiteSpace(character) || character is '/' or '@'))
        {
            return false;
        }

        if (System.Net.IPAddress.TryParse(host.Trim('[', ']'), out var address))
        {
            return !IsNonPublic(address);
        }

        var dot = host.LastIndexOf('.');
        return dot > 0 &&
               dot < host.Length - 1 &&
               !host.EndsWith(".home.arpa", StringComparison.Ordinal) &&
               !string.Equals(host, "home.arpa", StringComparison.Ordinal) &&
               !NonDomainTlds.Contains(host[(dot + 1)..]) &&
               !LocalDomainTlds.Contains(host[(dot + 1)..]) &&
               host.Split('.').All(label => label is { Length: > 0 and <= 63 } &&
                   char.IsAsciiLetterOrDigit(label[0]) &&
                   char.IsAsciiLetterOrDigit(label[^1]) &&
                   label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'));
    }

    private static bool InNetwork(System.Net.IPAddress address, string network, int prefixBits) =>
        HasPrefix(
            address.GetAddressBytes(),
            System.Net.IPAddress.Parse(network).GetAddressBytes(),
            prefixBits);

    private static bool HasPrefix(byte[] address, byte[] prefix, int prefixBits)
    {
        var fullBytes = prefixBits / 8;
        for (var index = 0; index < fullBytes; index++)
        {
            if (address[index] != prefix[index])
            {
                return false;
            }
        }

        var remainingBits = prefixBits % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (address[fullBytes] & mask) == (prefix[fullBytes] & mask);
    }
}

/// <summary>
/// Process-name hints for the agents Axiom supports. An agent's DNS query can come from its runtime
/// (node.exe, python.exe), so the executable path is matched as well as the process name.
/// </summary>
public static class AgentProcessMatcher
{
    private static readonly string[] NameHints =
    [
        "opencode",
        "openchamber",
        "claude",
        "codex",
        "cursor",
        "windsurf",
        "cline",
        "gemini",
        "copilot",
        "hermes",
        "openclaw",
        "aider",
        "goose",
    ];

    private static readonly string[] PathHints =
    [
        @"\opencode\",
        @"\openchamber\",
        @"\.opencode\",
        @"\@opencode-ai\",
        @"\@opencode-aidesktop\",
        @"\claude\",
        @"\.claude\",
        @"\codex\",
        @"\.codex\",
        @"\cursor\",
        @"\windsurf\",
        @"\cline\",
        @"\gemini\",
        @"\copilot\",
        @"\hermes\",
        @"\openclaw\",
        @"\aider\",
        @"\goose\",
    ];

    public static bool IsAgentProcess(string? processName, string? executablePath)
    {
        var name = (processName ?? string.Empty).Trim();
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            name = name[..^4];
        }

        if (NameHints.Any(hint => string.Equals(hint, name, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var path = executablePath ?? string.Empty;
        return path.Length > 0 &&
               PathHints.Any(hint => path.Contains(hint, StringComparison.OrdinalIgnoreCase));
    }
}
