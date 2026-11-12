// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Firewall;

/// <summary>
/// Read-back of what the OS currently holds for one managed rule. Presence alone is not proof
/// of enforcement: GPO, another product's rule or an allow override can still win.
/// </summary>
public sealed record EffectiveRuleReport
{
    public required Guid ManagedRuleId { get; init; }

    public required bool PresentInOs { get; init; }

    public required bool MatchesSpec { get; init; }

    public required FirewallAction? EffectiveAction { get; init; }

    public DateTimeOffset ObservedUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Human-readable limitations or conflicts observed during verification.</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>
    /// Set when the OS filter reported this rule as rejected (macOS <c>filter.rules</c>): the rule
    /// is published but not enforced. Null on Windows and when the filter accepted the rule.
    /// </summary>
    public string? FilterRejectionReason { get; init; }

    /// <summary>
    /// Whether <see cref="EffectiveAction"/> rests on a verified enforcement boundary: true when the
    /// OS filter is connected and has acknowledged the published generation containing this rule,
    /// false when the rule is only published (filter absent, disconnected, behind, or rejecting).
    /// Null on Windows, where the firewall applies rules synchronously and presence is enforcement.
    /// </summary>
    public bool? EnforcementVerified { get; init; }
}
