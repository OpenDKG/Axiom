// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Core.Firewall;

/// <summary>Observed state of one captured Axiom rule at the moment recovery reads it.</summary>
public enum OwnedRulePresence
{
    Absent = 0,
    Owned = 1,

    /// <summary>A rule with the same identity exists but its ownership metadata changed.</summary>
    ForeignOrChanged = 2,
}

/// <summary>
/// Narrow firewall surface used only by network recovery. It can remove one captured rule in one
/// direction; it never accepts an arbitrary name and it re-checks ownership metadata immediately
/// before removal. Authorization (elevated service or explicit administrator command) belongs to
/// the caller, because the emergency path runs outside the service host.
/// </summary>
public interface IOwnedRuleRecoveryAdapter
{
    Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct);

    Task<OwnedRulePresence> InspectOwnedRuleAsync(
        Guid managedRuleId,
        FirewallDirection direction,
        CancellationToken ct);

    Task<RuleApplyResult> RemoveCapturedOwnedRuleAsync(
        Guid managedRuleId,
        FirewallDirection direction,
        CancellationToken ct);
}
