// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Firewall;

/// <summary>A rule known to Axiom together with its last observed state.</summary>
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

    /// <summary>OS rule group read during capture; part of the ownership evidence.</summary>
    public string? OwnershipGroup { get; init; }

    /// <summary>OS rule description read during capture; part of the ownership evidence.</summary>
    public string? OwnershipDescription { get; init; }

    /// <summary>
    /// Linux: a new process of the app is refused at <c>connect()</c> (BPF verdict attached and read
    /// back). False = nft-only, installed/read back but not race-free (~1 s attribution window).
    /// Null on Windows and macOS, and for disabled rules.
    /// </summary>
    public bool? ConnectTimeBlockingProven { get; init; }

    /// <summary>Why <see cref="ConnectTimeBlockingProven"/> is what it is (Linux only).</summary>
    public string? CoverageReason { get; init; }
}
