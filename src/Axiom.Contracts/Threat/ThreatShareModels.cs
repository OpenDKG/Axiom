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
}

public sealed record ThreatShareItem(
    ThreatShareCandidate Candidate,
    ThreatShareState State,
    string Outcome,
    DateTimeOffset? AttemptedUtc)
{
    public string StateLabel => State switch
    {
        ThreatShareState.Submitted => "shared",
        ThreatShareState.Rejected => "rejected",
        ThreatShareState.Dismissed => "dismissed",
        _ => "pending review",
    };
}

/// <summary>The preview list and counters the Agents page shows.</summary>
public sealed record ThreatShareQueueStatus
{
    public required int Pending { get; init; }

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
                if (!raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                    !raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                return raw.TrimEnd('/');
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

    /// <summary>Loopback, link-local and RFC 1918/ULA addresses are not shareable indicators.</summary>
    private static bool IsNonPublic(System.Net.IPAddress address)
    {
        if (System.Net.IPAddress.IsLoopback(address) ||
            address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
        {
            return true;
        }

        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 169 && bytes[1] == 254) ||
               bytes[0] == 127;
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
