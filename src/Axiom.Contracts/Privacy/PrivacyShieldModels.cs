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
    DateTimeOffset BlockedUtc)
{
    /// <summary>Name of the process whose DNS query was blocked, when Windows exposes it.</summary>
    public string AppName { get; init; } = string.Empty;

    /// <summary>Local executable path, when readable; empty for protected or exited processes.</summary>
    public string AppPath { get; init; } = string.Empty;

    /// <summary>
    /// The nearest ancestor that is a known agent, when the query came through that agent's tool
    /// (an agent shells out to curl, git or nslookup, so the querying process is the tool child).
    /// </summary>
    public string AgentName { get; init; } = string.Empty;

    public string AgentPath { get; init; } = string.Empty;

    /// <summary>The policy suffix that matched, which may be a parent of the queried domain.</summary>
    public string MatchedRule { get; init; } = string.Empty;

    /// <summary>Local blocklist source id, or "starter"/"custom". Used only for local provenance.</summary>
    public string SourceId { get; init; } = string.Empty;

    public string SourceName { get; init; } = string.Empty;

    /// <summary>Pinned digest or last-update timestamp of the source, when available.</summary>
    public string SourceVersion { get; init; } = string.Empty;

    public string AxiomVersion { get; init; } = string.Empty;

    /// <summary>Why the local resolver blocked it; never sent to Blackbox as free text.</summary>
    public string DetectionReason { get; init; } = string.Empty;

    /// <summary>True when the match came from a downloaded public list rather than a local rule.</summary>
    public bool IsListDerived { get; init; }

    /// <summary>True when the DNS lookup was blocked, not fetched; this is not a completed download.</summary>
    public bool LookupBlocked { get; init; }

    public string AgentDisplay => string.IsNullOrWhiteSpace(AgentName) ? "unknown agent" : AgentName;

    public string AppDisplay => string.IsNullOrWhiteSpace(AppName) ? "unknown app" : AppName;

    public string CategoryText => Category.ToString();
}

public sealed record PrivacyShieldSourceInfo(
    string Id,
    string Name,
    string Url,
    string License,
    PrivacyCategory Category,
    string Description,
    string Sha256 = "");

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
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@924bb2a8306e609ae8b0113c2b676f5fde072d16/wildcard/pro-onlydomains.txt",
            "GPL-3.0",
            PrivacyCategory.Ads | PrivacyCategory.Tracking | PrivacyCategory.Analytics,
            "Broad ads, trackers and telemetry; pinned to a commit and checked by digest.",
            "ECF78F54E65FD78F70FB1636CE6BBAD563306246F8C00CDCDCE18B1C8BE01A7A"),
        new(
            "oisd-big",
            "OISD Big",
            "https://big.oisd.nl/domainswild",
            "GPL-3.0",
            PrivacyCategory.Ads | PrivacyCategory.Tracking,
            "Balanced ads/tracking list with wildcard domains; malware is covered by the dedicated malware source."),
        new(
            "windowsspyblocker",
            "WindowsSpyBlocker telemetry",
            "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
            "MIT",
            PrivacyCategory.Telemetry,
            "Windows telemetry-focused hosts list; inspect upstream changes before updating."),
        new(
            "blocklistproject-ads",
            "The Block List Project - Ads",
            "https://blocklistproject.github.io/Lists/ads.txt",
            "Unlicense",
            PrivacyCategory.Ads,
            "Public-domain ads list; no attribution or permission gate, but review upstream changes."),
        new(
            "blocklistproject-tracking",
            "The Block List Project - Tracking",
            "https://blocklistproject.github.io/Lists/tracking.txt",
            "Unlicense",
            PrivacyCategory.Tracking,
            "Public-domain tracking list; no attribution or permission gate, but review upstream changes."),
        new(
            "urlhaus-domains",
            "URLhaus malicious domains",
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
            "MIT",
            PrivacyCategory.Malware,
            "Malware-only domains from the abuse.ch URLhaus feed, compiled by malware-filter (MIT, " +
            "updated every 12 hours). Matches stay local with source/version provenance and are not " +
            "proposed to the community; they would only echo the same public list."),
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
