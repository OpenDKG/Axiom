// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Firewall;

/// <summary>
/// Result of probing the platform firewall adapter. A <c>null</c> flag means "not probed",
/// never "supported". FND-001 reports <see cref="FirewallCapabilityStatus.Unavailable"/>.
/// </summary>
public sealed record FirewallCapabilityReport
{
    public required FirewallCapabilityStatus Status { get; init; }

    /// <summary>Short, user-presentable reason. Required when the adapter is not available.</summary>
    public string? Reason { get; init; }

    public bool? FirewallServiceRunning { get; init; }

    public bool? ManagedRulesReadable { get; init; }

    public int? ManagedRuleCount { get; init; }

    public DateTimeOffset ProbedUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Enforcement report of the OS filter (macOS AxiomFilter <c>filter.rules</c> event). Null on
    /// Windows and until the extension has reported once.
    /// </summary>
    public FilterEnforcementReport? FilterEnforcement { get; init; }
}

/// <summary>One rule the OS filter refused to enforce, with its reason.</summary>
public sealed record FilterRuleRejection
{
    /// <summary>The managed rule id as written to the filter table, or <c>#&lt;index&gt;</c> when it had none.</summary>
    public required string RuleId { get; init; }

    public required string Reason { get; init; }
}

/// <summary>
/// What the OS filter enforces right now, as the filter itself reported it (macOS only; Windows
/// Firewall has no equivalent and leaves it null).
/// </summary>
public sealed record FilterEnforcementReport
{
    /// <summary>Generation of the rule table in force (-1 before any table loaded).</summary>
    public long Generation { get; init; } = -1;

    /// <summary>Enabled rules the filter enforces.</summary>
    public int AppliedRuleCount { get; init; }

    /// <summary>Rules the filter skipped; they are published but <b>not</b> enforced.</summary>
    public IReadOnlyList<FilterRuleRejection> RejectedRules { get; init; } = [];

    /// <summary>Why the whole rules file was rejected (the previous table stays in force); null when it loaded.</summary>
    public string? FileError { get; init; }

    /// <summary>Flow events the filter dropped so far; a value above zero means the flow table is incomplete.</summary>
    public long DroppedEvents { get; init; }

    public DateTimeOffset ReportedUtc { get; init; }
}
