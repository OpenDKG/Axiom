// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Firewall;

namespace Axiom.Core.Firewall;

/// <summary>
/// Deterministic naming contract for OS rules owned by Axiom.
/// <para>
/// Format: <c>Axiom::{rule-id:D}::{OUT|IN}</c>. The identifier lets uninstall and
/// recovery remove exactly our rules without wildcard deletes of third-party rules.
/// </para>
/// </summary>
public static class OwnedRuleName
{
    public const string Prefix = "Axiom::";

    /// <summary>Read-only recognition of rules created before the Axiom rename.</summary>
    public const string LegacyPrefix = LegacyIdentity.RulePrefix;

    public const string OutboundToken = "OUT";

    public const string InboundToken = "IN";

    private const string Separator = "::";

    public static string Create(Guid managedRuleId, FirewallDirection direction)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        return string.Concat(Prefix, managedRuleId.ToString("D"), Separator, DirectionToken(direction));
    }

    public static string DirectionToken(FirewallDirection direction) => direction switch
    {
        FirewallDirection.Outbound => OutboundToken,
        FirewallDirection.Inbound => InboundToken,
        _ => throw new ArgumentOutOfRangeException(nameof(direction), direction, "Undefined direction."),
    };

    /// <summary>Strict parse; returns false for any name that does not follow the contract exactly.</summary>
    public static bool TryParse(string? name, out Guid managedRuleId, out FirewallDirection direction)
    {
        managedRuleId = Guid.Empty;
        direction = default;

        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        var prefix = name.StartsWith(Prefix, StringComparison.Ordinal)
            ? Prefix
            : name.StartsWith(LegacyPrefix, StringComparison.Ordinal)
                ? LegacyPrefix
                : null;
        if (prefix is null)
        {
            return false;
        }

        var remainder = name[prefix.Length..];
        var parts = remainder.Split(Separator, StringSplitOptions.None);
        if (parts.Length != 2)
        {
            return false;
        }

        if (!Guid.TryParseExact(parts[0], "D", out var parsedId) || parsedId == Guid.Empty)
        {
            return false;
        }

        FirewallDirection parsedDirection;
        if (string.Equals(parts[1], OutboundToken, StringComparison.Ordinal))
        {
            parsedDirection = FirewallDirection.Outbound;
        }
        else if (string.Equals(parts[1], InboundToken, StringComparison.Ordinal))
        {
            parsedDirection = FirewallDirection.Inbound;
        }
        else
        {
            return false;
        }

        managedRuleId = parsedId;
        direction = parsedDirection;
        return true;
    }

    /// <summary>
    /// Conservative ownership test used by enumeration and uninstall: anything carrying our prefix
    /// is treated as ours, even when the rest of the name is malformed.
    /// </summary>
    public static bool IsOwned(string? name) =>
        !string.IsNullOrWhiteSpace(name) &&
        (name.StartsWith(Prefix, StringComparison.Ordinal) ||
         name.StartsWith(LegacyPrefix, StringComparison.Ordinal));

    /// <summary>Maps an old OS rule name to the Axiom display contract.</summary>
    public static string ToDisplayName(string name) =>
        name.StartsWith(LegacyPrefix, StringComparison.Ordinal)
            ? Prefix + name[LegacyPrefix.Length..]
            : name;

    /// <summary>The old physical rule name, used only for targeted removal during migration.</summary>
    public static string ToLegacyName(string name) =>
        name.StartsWith(Prefix, StringComparison.Ordinal)
            ? LegacyPrefix + name[Prefix.Length..]
            : name;
}
