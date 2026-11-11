// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Firewall;

namespace Axiom.Core.Firewall;

/// <summary>
/// Ownership evidence for recovery. A rule is Axiom's only when its name follows the strict
/// identity contract and the OS metadata still carries one of Axiom's ownership markers. The name
/// prefix alone is not enough, because recovery deletes rules.
/// </summary>
public static class OwnedRuleOwnership
{
    public const string GroupName = "Axiom";

    /// <summary>True when the persisted managed rule has identity and metadata recovery can trust.</summary>
    public static bool IsRecoverable(ManagedRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        return rule.ManagedRuleId != Guid.Empty &&
               OwnedRuleName.TryParse(rule.OsRuleName, out var id, out var direction) &&
               id == rule.ManagedRuleId &&
               direction == rule.Spec.Direction &&
               HasOwnershipMetadata(rule.OwnershipGroup, rule.OwnershipDescription);
    }

    /// <summary>Metadata check used both at capture and immediately before a recovery removal.</summary>
    public static bool HasOwnershipMetadata(string? group, string? description) =>
        IsOwnedGroup(group) || DescriptionHasOwnedMarker(description);

    private static bool IsOwnedGroup(string? group) =>
        !string.IsNullOrWhiteSpace(group) &&
        (string.Equals(group.Trim(), GroupName, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(group.Trim(), LegacyIdentity.ProductName, StringComparison.OrdinalIgnoreCase));

    private static bool DescriptionHasOwnedMarker(string? description) =>
        !string.IsNullOrWhiteSpace(description) &&
        (description.TrimStart().StartsWith(GroupName, StringComparison.OrdinalIgnoreCase) ||
         description.TrimStart().StartsWith(LegacyIdentity.ProductName, StringComparison.OrdinalIgnoreCase));
}
