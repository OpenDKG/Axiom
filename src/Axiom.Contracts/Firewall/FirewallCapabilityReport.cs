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

    /// <summary>
    /// Known limitations of the enforcement boundary on this host (Linux: the attribution loop's
    /// exec race, an inactive connect-time BPF layer). Empty on Windows and macOS.
    /// </summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];

    /// <summary>
    /// Linux only: live state of the connect-time (BPF) layer as the running daemon holds it, so
    /// <c>axiomd --doctor</c> and the UI never infer health from pin files. Null on Windows and macOS.
    /// </summary>
    public ConnectTimeLayerReport? ConnectTimeLayer { get; init; }
}

/// <summary>
/// Live state of the Linux connect-time verdict layer (docs/LINUX_EBPF.md). <see cref="Healthy"/> is
/// true only while the layer is attached, its last map sync was written and read back, no stale
/// entry/program is left and no rule removal is waiting for its BPF cleanup.
/// </summary>
public sealed record ConnectTimeLayerReport
{
    /// <summary>
    /// <c>active</c>, <c>inactive</c> (probe said no: nft-only), <c>neutralised</c> (detached itself),
    /// <c>degraded</c> (stale verdicts attached), <c>stale_programs</c> (a previous daemon's programs
    /// could not be detached), or <c>not_configured</c>.
    /// </summary>
    public required string State { get; init; }

    public required bool Healthy { get; init; }

    public bool Attached { get; init; }

    public string Status { get; init; } = string.Empty;

    /// <summary>Generation of the last map sync (null before the first).</summary>
    public long? Generation { get; init; }

    /// <summary>The last sync's map contents were read back and equal the plan.</summary>
    public bool MapsVerified { get; init; }

    /// <summary>Rules whose new processes are refused at connect() (BPF verdict read back).</summary>
    public IReadOnlyList<Guid> ConnectTimeProvenRules { get; init; } = [];

    /// <summary>Enabled rules enforced by nftables alone (installed/read back, not race-free).</summary>
    public IReadOnlyList<Guid> NftOnlyRules { get; init; } = [];

    /// <summary>Removed rules whose BPF verdict cleanup is not confirmed (persisted across restarts).</summary>
    public IReadOnlyList<Guid> PendingRemovals { get; init; } = [];

    public IReadOnlyList<string> FailedDeletes { get; init; } = [];

    public IReadOnlyList<string> FailedUpdates { get; init; } = [];
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
    /// <summary>Derived enforcement state of <see cref="PublishedGeneration"/> (review 2026-11-12: published is not enforced).</summary>
    public FilterEnforcementState State { get; init; }

    /// <summary>The filter holds a live connection to the service right now (not "was seen recently").</summary>
    public bool Connected { get; init; }

    /// <summary>Generation the service last published to the filter.</summary>
    public long PublishedGeneration { get; init; }

    /// <summary>Generation the filter last acknowledged with a <c>filter.rules</c> event without a file error; null before the first.</summary>
    public long? AckedGeneration { get; init; }

    /// <summary>Last time anything arrived from the filter (diagnostic; does not imply enforcement).</summary>
    public DateTimeOffset? LastSeenUtc { get; init; }

    /// <summary>Time of the last acknowledgement (<see cref="AckedGeneration"/>).</summary>
    public DateTimeOffset? LastAckUtc { get; init; }

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
