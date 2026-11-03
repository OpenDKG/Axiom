// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netrigil.Contracts.Firewall;

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
}
