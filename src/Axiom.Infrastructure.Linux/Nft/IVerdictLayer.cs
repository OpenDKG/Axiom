// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>
/// An optional enforcement layer fed by the same rule set and generation as the nftables table
/// (docs/LINUX_EBPF.md): the adapter calls <see cref="SyncAsync"/> after every successful publish.
/// nftables stays the primary boundary; a layer may be inactive (missing toolchain, kernel
/// without BTF, unit without the capabilities) and must say so in <see cref="Status"/>.
/// The layer is part of the effective state (PR #276 review, LNX-1): a map write that failed is
/// returned in the <see cref="LayerSyncResult"/>, never only logged, so the adapter can refuse to
/// call a rule applied or removed while the layer still disagrees with the table.
/// </summary>
public interface IVerdictLayer
{
    /// <summary>True while the layer enforces verdicts.</summary>
    bool Active { get; }

    /// <summary>One line for capabilities/doctor: what the layer does or why it is inactive.</summary>
    string Status { get; }

    /// <summary>
    /// True after the layer detached itself because a stale verdict could not be removed
    /// (docs/LINUX_EBPF.md §10): nothing of the layer enforces until it is re-attached.
    /// </summary>
    bool Neutralised => false;

    /// <summary>
    /// True when Axiom programs of a previous daemon are still attached and could not be detached
    /// at start: their unpinned maps may still hold verdicts of removed rules, so the layer refused
    /// to load a second set and nothing about the connect-time state can be trusted.
    /// </summary>
    bool StaleProgramsAttached => false;

    /// <summary>
    /// True while the layer cannot confirm whether its programs are attached (<c>bpftool cgroup show</c>
    /// failed or printed something unreadable). Unknown is never "not attached": the layer keeps its pins,
    /// loads no second set, and removals stay pending until a readable read-back confirms them.
    /// </summary>
    bool AttachmentUnknown => false;

    /// <summary>
    /// True while the layer is starting (docs/LINUX_EBPF.md §11): not started yet, or a new program set
    /// is attached next to a previous daemon's set and its maps are not populated and read back yet.
    /// Whatever enforces meanwhile is not verified, so nothing may be reported as connect-time proven.
    /// </summary>
    bool Pending => false;

    /// <summary>
    /// Rules whose executable identity changed since the last sync (the file at the rule's path was
    /// replaced, e.g. by a package upgrade's rename(2)): the written exe key no longer matches it.
    /// </summary>
    IReadOnlyList<Guid> StaleExeKeys(IReadOnlyList<ManagedRule> rules) => [];

    /// <summary>
    /// Live check that the layer's programs are still attached (another tool may have detached them
    /// between syncs). Marks the layer neutralised when they are not; returns whether it is attached.
    /// </summary>
    bool CheckAttached() => Active;

    /// <summary>
    /// Reconciles the layer's state with the enabled rules of this generation (bounded retries,
    /// read-back verification, neutralisation on persistent failure) and reports the outcome.
    /// Never throws for a bpftool failure.
    /// </summary>
    Task<LayerSyncResult> SyncAsync(IReadOnlyList<ManagedRule> rules, long generation, CancellationToken ct);
}

/// <summary>A verdict layer with a daemon lifetime, driven by <see cref="NftEnforcementSupervisor"/>.</summary>
public interface IEnforcementLayer : IVerdictLayer
{
    /// <summary>Probes, loads and attaches; never throws — an unusable layer reports <see cref="IVerdictLayer.Status"/>.</summary>
    Task StartAsync(CancellationToken ct);

    /// <summary>Detaches and removes everything the layer created; idempotent.</summary>
    Task StopAsync();

    /// <summary>
    /// Stop for a restart (docs/LINUX_EBPF.md §11): leaves the attached programs and their pinned maps
    /// enforcing for the next daemon, which replaces them make-before-break. Layers without a
    /// hand-over detach like <see cref="StopAsync"/>.
    /// </summary>
    Task HandOverAsync() => StopAsync();

    /// <summary>Streams the layer's flow events into the sink until cancelled (restarting its source on exit).</summary>
    Task RunEventsAsync(CancellationToken ct);
}

/// <summary>One map write the layer could not complete (after its retries).</summary>
public sealed record LayerSyncFailure(string Operation, string Map, string KeyHex, Guid? RuleId, string Describe, string Error)
{
    public override string ToString() => $"{Operation} {Describe}: {Error}";
}

/// <summary>A rule the layer does not express; nftables alone enforces it.</summary>
public sealed record LayerUncoveredRule(Guid RuleId, string Reason);

/// <summary>
/// Outcome of one <see cref="IVerdictLayer.SyncAsync"/>: what the layer enforces for the generation
/// after retries and read-back. <see cref="Applied"/> is the "every desired entry written and no
/// stale entry left" verdict the adapter folds into rule state; <see cref="StaleEntriesCanBlock"/>
/// is the dangerous case (a removed rule still blocks at connect time).
/// </summary>
public sealed record LayerSyncResult
{
    /// <summary>Generation the sync was asked for.</summary>
    public required long Generation { get; init; }

    /// <summary>Programs attached (the layer enforces) after the sync.</summary>
    public required bool Attached { get; init; }

    /// <summary>The pin directory with the maps exists.</summary>
    public bool Pinned { get; init; }

    /// <summary>Every desired entry was written and every stale entry deleted (write results).</summary>
    public bool Applied { get; init; }

    /// <summary>A read-back (<c>bpftool map dump</c>) confirmed the map contents equal the plan.</summary>
    public bool Verified { get; init; }

    /// <summary>The layer detached its own programs because a stale entry could not be removed.</summary>
    public bool Neutralised { get; init; }

    /// <summary>Whether the programs are attached could not be read (see <see cref="IVerdictLayer.AttachmentUnknown"/>).</summary>
    public bool AttachmentUnknown { get; init; }

    /// <summary>Write passes made (1 = no retry).</summary>
    public int Attempts { get; init; }

    public IReadOnlyList<LayerSyncFailure> FailedUpdates { get; init; } = [];

    public IReadOnlyList<LayerSyncFailure> FailedDeletes { get; init; } = [];

    /// <summary>Rules the layer enforces at connect time (unscoped outbound block rules).</summary>
    public IReadOnlyList<Guid> CoveredRules { get; init; } = [];

    /// <summary>Rules left to nftables alone, with the reason.</summary>
    public IReadOnlyList<LayerUncoveredRule> Uncovered { get; init; } = [];

    public string Status { get; init; } = string.Empty;

    /// <summary>
    /// A verdict the plan no longer wants is still in an attached map (or one whose attachment cannot be
    /// confirmed): it can block traffic the rule set does not block.
    /// </summary>
    public bool StaleEntriesCanBlock => (Attached || AttachmentUnknown) && FailedDeletes.Count > 0;

    /// <summary>Layer inactive: nothing written, nothing enforced by it.</summary>
    public static LayerSyncResult Inactive(long generation, string status, bool pinned = false, bool neutralised = false) => new()
    {
        Generation = generation,
        Attached = false,
        Pinned = pinned,
        Applied = false,
        Verified = false,
        Neutralised = neutralised,
        Attempts = 0,
        Status = status,
    };

    /// <summary>Rule ids named by the failures (null when a failure names no rule).</summary>
    public IEnumerable<Guid> FailedRuleIds => FailedUpdates.Concat(FailedDeletes).Where(failure => failure.RuleId is not null).Select(failure => failure.RuleId!.Value).Distinct();
}
