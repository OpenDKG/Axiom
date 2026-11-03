// SPDX-License-Identifier: GPL-3.0-or-later
namespace LocalFirewall.Contracts.Firewall;

/// <summary>A rule known to LocalFirewall together with its last observed state.</summary>
public sealed record ManagedRule
{
    public required Guid ManagedRuleId { get; init; }

    /// <summary>Deterministic OS rule name; empty while the rule has not been applied.</summary>
    public required string OsRuleName { get; init; }

    public required RuleSpec Spec { get; init; }

    public RuleState State { get; init; } = RuleState.Unknown;

    public DateTimeOffset? LastVerifiedUtc { get; init; }

    /// <summary>Machine-readable failure reason, never a raw exception dump.</summary>
    public string? LastErrorCode { get; init; }
}
