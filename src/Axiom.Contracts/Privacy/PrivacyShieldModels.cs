// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Privacy;

[Flags]
public enum PrivacyCategory
{
    None = 0,
    Telemetry = 1,
    Ads = 2,
    Tracking = 4,
    Analytics = 8,
    Malware = 16,
    Custom = 32,
}

public enum PrivacyShieldProfile
{
    Basic = 0,
    Balanced = 1,
    Strict = 2,
}

public static class PrivacyShieldCategories
{
    public static PrivacyCategory ForProfile(PrivacyShieldProfile profile) => profile switch
    {
        PrivacyShieldProfile.Basic => PrivacyCategory.Telemetry,
        PrivacyShieldProfile.Strict => PrivacyCategory.Telemetry |
                                       PrivacyCategory.Ads |
                                       PrivacyCategory.Tracking |
                                       PrivacyCategory.Analytics |
                                       PrivacyCategory.Malware |
                                       PrivacyCategory.Custom,
        _ => PrivacyCategory.Telemetry |
             PrivacyCategory.Ads |
             PrivacyCategory.Tracking |
             PrivacyCategory.Analytics |
             PrivacyCategory.Custom,
    };

    public static string Label(PrivacyCategory category) => category switch
    {
        PrivacyCategory.Telemetry => "Telemetry",
        PrivacyCategory.Ads => "Ads",
        PrivacyCategory.Tracking => "Tracking",
        PrivacyCategory.Analytics => "Analytics",
        PrivacyCategory.Malware => "Malware",
        PrivacyCategory.Custom => "Custom",
        _ => "Unknown",
    };
}

public sealed record PrivacyShieldSettings
{
    public bool Enabled { get; init; }

    public PrivacyShieldProfile Profile { get; init; } = PrivacyShieldProfile.Balanced;

    public PrivacyCategory Categories { get; init; } =
        PrivacyShieldCategories.ForProfile(PrivacyShieldProfile.Balanced);

    /// <summary>Loopback port for the opt-in resolver. 53 is required for normal Windows DNS use.</summary>
    public int Port { get; init; } = 53;

    /// <summary>Optional upstream IP or IP:port. Empty uses the current Windows DNS servers.</summary>
    public string UpstreamDns { get; init; } = string.Empty;

    public IReadOnlyList<string> AllowedDomains { get; init; } = [];

    public IReadOnlyList<string> BlockedDomains { get; init; } = [];

    public IReadOnlyList<string> EnabledSourceIds { get; init; } = [];

    /// <summary>Reserved for a future bounded query log; the initial implementation keeps counts only.</summary>
    public bool LogQueries { get; init; }
}

public sealed record PrivacyShieldTopDomain(string Domain, long Count);

public sealed record PrivacyShieldBlockedEvent(
    string Domain,
    PrivacyCategory Category,
    DateTimeOffset BlockedUtc);

public sealed record PrivacyShieldSourceInfo(
    string Id,
    string Name,
    string Url,
    string License,
    PrivacyCategory Category,
    string Description);

public sealed record PrivacyShieldStoredRule(
    string Domain,
    string SourceId,
    PrivacyCategory Category,
    DateTimeOffset UpdatedUtc);

public sealed record PrivacyShieldSourceStatus(
    string Id,
    string Name,
    string License,
    bool Enabled,
    int Entries,
    DateTimeOffset? UpdatedUtc,
    string? Error);

public static class PrivacyShieldSourceCatalog
{
    public static IReadOnlyList<PrivacyShieldSourceInfo> All { get; } =
    [
        new(
            "hagezi-pro",
            "HaGeZi Multi PRO",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
            "GPL-3.0",
            PrivacyCategory.Ads | PrivacyCategory.Tracking | PrivacyCategory.Analytics,
            "Broad ads, trackers and telemetry; verify current upstream license and size."),
        new(
            "oisd-big",
            "OISD Big",
            "https://big.oisd.nl/domainswild",
            "GPL-3.0",
            PrivacyCategory.Ads | PrivacyCategory.Tracking | PrivacyCategory.Malware,
            "Balanced ads/tracking/malware list with wildcard domains."),
        new(
            "windowsspyblocker",
            "WindowsSpyBlocker telemetry",
            "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
            "MIT",
            PrivacyCategory.Telemetry,
            "Windows telemetry-focused hosts list; inspect upstream changes before updating."),
    ];
}

public sealed record PrivacyShieldStatus
{
    public required string State { get; init; }

    public required bool Enabled { get; init; }

    public required bool Running { get; init; }

    public required int Port { get; init; }

    public required string BindAddress { get; init; }

    public required string Upstream { get; init; }

    public required long Queries { get; init; }

    public required long Allowed { get; init; }

    public required long Blocked { get; init; }

    public required long Errors { get; init; }

    public required int RuleCount { get; init; }

    public PrivacyShieldSettings Settings { get; init; } = new();

    public IReadOnlyList<PrivacyShieldSourceStatus> Sources { get; init; } = [];

    public IReadOnlyList<PrivacyShieldTopDomain> TopBlocked { get; init; } = [];

    /// <summary>Bounded in-memory recent blocks; this is not persisted DNS history.</summary>
    public IReadOnlyList<PrivacyShieldBlockedEvent> RecentBlocked { get; init; } = [];

    /// <summary>Bounded local blocked-query history, newest first. Never contains allowed queries.</summary>
    public IReadOnlyList<PrivacyShieldBlockedEvent> BlockedHistory { get; init; } = [];

    public string Detail { get; init; } = string.Empty;

    public string? LastError { get; init; }
}
