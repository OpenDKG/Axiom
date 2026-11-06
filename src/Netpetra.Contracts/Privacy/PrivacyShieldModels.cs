// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.Contracts.Privacy;

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

    /// <summary>Reserved for a future bounded query log; the initial implementation keeps counts only.</summary>
    public bool LogQueries { get; init; }
}

public sealed record PrivacyShieldTopDomain(string Domain, long Count);

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

    public IReadOnlyList<PrivacyShieldTopDomain> TopBlocked { get; init; } = [];

    public string Detail { get; init; } = string.Empty;

    public string? LastError { get; init; }
}
