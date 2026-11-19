// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Firewall;

/// <summary>
/// Outcome of an apply/remove request. Success only means the adapter reported a verified
/// read-back; it never implies that a specific packet was blocked.
/// </summary>
public sealed record RuleApplyResult
{
    public required bool Success { get; init; }

    public required Guid ManagedRuleId { get; init; }

    public required RuleState State { get; init; }

    public string? OsRuleName { get; init; }

    public string? ErrorCode { get; init; }

    public string? ErrorMessage { get; init; }

    public DateTimeOffset? VerifiedUtc { get; init; }

    /// <summary>
    /// Linux: the applied rule refuses a fresh process at <c>connect()</c> (BPF verdict read back);
    /// false = nft-only, not race-free. Null on Windows and macOS.
    /// </summary>
    public bool? ConnectTimeBlockingProven { get; init; }

    /// <summary>Why <see cref="ConnectTimeBlockingProven"/> is what it is (Linux only).</summary>
    public string? CoverageReason { get; init; }
}
