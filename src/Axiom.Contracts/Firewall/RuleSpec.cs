// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Firewall;

/// <summary>
/// Declarative description of a single firewall rule owned by Axiom.
/// <para>
/// The spec is the durable intent; the Windows rule is a derived artefact named
/// <c>Axiom::{ManagedRuleId}::{OUT|IN}</c>. See <c>OwnedRuleName</c> in
/// <c>Axiom.Core</c> for the naming contract.
/// </para>
/// </summary>
public sealed record RuleSpec
{
    /// <summary>Identity owned by this application; never derived from the OS rule name alone.</summary>
    public required Guid ManagedRuleId { get; init; }

    /// <summary>Absolute, normalised executable path. Windows Firewall rules are path-bound.</summary>
    public required string AppPath { get; init; }

    public required FirewallDirection Direction { get; init; }

    public required FirewallAction Action { get; init; }

    public FirewallProfile Profiles { get; init; } = FirewallProfile.All;

    public NetworkProtocol Protocol { get; init; } = NetworkProtocol.Any;

    /// <summary>Optional IPv4/IPv6 addresses or CIDR ranges. Empty means "any".</summary>
    public IReadOnlyList<string> RemoteAddresses { get; init; } = [];

    /// <summary>Optional port list/range, for example <c>443</c> or <c>8000-8100</c>. Null means "any".</summary>
    public string? RemotePorts { get; init; }

    public bool Enabled { get; init; } = true;

    public string? Description { get; init; }

    /// <summary>Operator identity (Windows SID or account name) recorded in the audit trail.</summary>
    public required string CreatedBy { get; init; }

    public int SchemaVersion { get; init; } = RuleSpecSchema.CurrentVersion;
}
