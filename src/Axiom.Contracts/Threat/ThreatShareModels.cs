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

    public string TypeLabel => IndicatorType;

    public string SourceLabel => Source switch
    {
        ThreatShareSource.PrivacyShield => "Privacy Shield",
        ThreatShareSource.AiAnalyst => "AI Analyst",
        _ => "Axiom",
    };
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

    /// <summary>Button label: an ambiguous item needs a deliberate retry, not another "Share".</summary>
    public string ActionLabel => State == ThreatShareState.Unverified ? "Retry" : "Share";

    public string StateLabel => State switch
    {
        ThreatShareState.Submitted => "shared",
        ThreatShareState.Rejected => "rejected",
        ThreatShareState.Dismissed => "dismissed",
        ThreatShareState.Deferred => "deferred",
        ThreatShareState.Unverified => "awaiting confirmation",
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

    /// <summary>Closed reason codes from the Blackbox report schema.</summary>
    public static IReadOnlyList<string> Reasons { get; } =
    [
        "phishing",
        "malware-delivery",
        "command-and-control",
        "credential-harvest",
        "exfil-endpoint",
        "scam",
        "injection-host",
    ];

    /// <summary>
    /// Only contexts Axiom can state truthfully: an agent tool fetched the indicator, or an agent
    /// (the AI Analyst) produced it from its tool output. A DNS block on its own is not a context.
    /// </summary>
    public static IReadOnlyList<string> Contexts { get; } = ["fetched-by-tool", "in-tool-output"];

    /// <summary>File-like "TLDs" that appear in free text but are never shareable domains.</summary>
    private static readonly HashSet<string> NonDomainTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "log", "json", "txt", "xml", "csv", "md", "ps1", "bat", "cmd", "msi",
        "tmp", "dat", "db", "sqlite", "pem", "key", "crt", "ini", "yaml", "yml", "zip", "gz",
        "pdf", "docx", "xlsx", "png", "jpg", "html", "lnk",
    };

    public static bool IsSupported(string indicatorType, string reason, string context) =>
        IndicatorTypes.Contains(indicatorType, StringComparer.OrdinalIgnoreCase) &&
        Reasons.Contains(reason, StringComparer.OrdinalIgnoreCase) &&
        Contexts.Contains(context, StringComparer.OrdinalIgnoreCase);

    /// <summary>Builds the stable queue id and the value Blackbox hashes, or null when invalid.</summary>
    public static string? Normalize(string indicatorType, string value)
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
                if (raw.Length is 0 or > 253 || raw.IndexOf('.') < 0 ||
                    NonDomainTlds.Contains(raw[(raw.LastIndexOf('.') + 1)..]) ||
                    raw.Any(character => char.IsWhiteSpace(character) || character is '/' or ':' or '@'))
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
                var hostForUrl = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
                if (hostForUrl.Contains(':', StringComparison.Ordinal) &&
                    !hostForUrl.StartsWith('['))
                {
                    hostForUrl = "[" + hostForUrl + "]";
                }

                var port = uri.IsDefaultPort ? string.Empty : ":" + uri.Port;
                var normalizedUrl = $"{uri.Scheme}://{hostForUrl}{port}{uri.AbsolutePath}"
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
               !host.Contains("..", StringComparison.Ordinal) &&
               !NonDomainTlds.Contains(host[(dot + 1)..]);
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
