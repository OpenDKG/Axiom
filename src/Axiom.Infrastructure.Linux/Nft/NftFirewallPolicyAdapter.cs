// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>Files the engine owns under the daemon state directory (<c>/var/lib/axiom/filter</c>).</summary>
public sealed record NftEnginePaths(string FilterDirectory)
{
    public string ManagedRulesFile => Path.Combine(FilterDirectory, "managed-rules.json");

    /// <summary>The last generated <c>nft -f</c> batch, kept for <c>--doctor</c> and support bundles.</summary>
    public string RulesFile => Path.Combine(FilterDirectory, "rules.nft");
}

/// <summary>
/// Linux firewall adapter: the "OS firewall" is <c>table inet axiom</c> built by
/// <see cref="NftRuleCompiler"/> and applied atomically through <see cref="NftTable"/>; rules are
/// keyed on per-app cgroups owned by <see cref="AppCgroupManager"/>. Like the macOS adapter it keeps
/// its own durable record of Axiom-owned rules (<c>managed-rules.json</c>, 0600), republishes a new
/// generation after every change, and reports the outcome in the same shape (<see cref="FilterEnforcementReport"/>
/// plus <c>filter.hello</c>/<c>filter.rules</c> NDJSON lines on the event sink) so the daemon and UI
/// need no Linux-specific code. Writes require the same gate as Windows/macOS.
/// Publishing is not enforcing (macOS review 2026-11-12 P0 #2/#3, High #4 applied to nftables):
/// <c>nft -f</c> is synchronous and atomic, but a rule is <see cref="RuleState.Applied"/> only once
/// (a) the batch succeeded, (b) <c>nft -j list table inet axiom</c> read back exactly the published
/// generation with the rule's comment in it and (c) the rule's app cgroup exists and every live
/// process of the app was herded; otherwise it is <see cref="RuleState.Pending"/> with the reason,
/// and a rule the compiler refused (bad address, unreachable app) is <see cref="RuleState.Failed"/>.
/// <see cref="VerifyAsync"/> and <see cref="GetCapabilitiesAsync"/> read the live table every time;
/// <c>managed-rules.json</c> alone never proves anything. The table can vanish under the daemon
/// (<c>nft flush ruleset</c> by another tool): that is the Linux counterpart of the macOS filter
/// disconnect and degrades the report at once (<see cref="MarkTableLostAsync"/>, called by the watcher).
/// </summary>
public sealed class NftFirewallPolicyAdapter : IFirewallPolicyAdapter, IOwnedRuleRecoveryAdapter, IDisposable
{
    private static readonly JsonSerializerOptions StateJson = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly NftEnginePaths _paths;
    private readonly NftTable _table;
    private readonly AppCgroupManager _cgroups;
    private readonly IFilterEventSink _events;
    private readonly Func<bool> _writeGate;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _reportGate = new();
    private FilterEnforcementReport? _enforcement;
    private NftCompilation? _lastCompilation;
    private bool _tableApplied;
    private long _published = -1;
    private DateTimeOffset? _lastSeenUtc;
    private DateTimeOffset? _lastAckUtc;
    private IReadOnlyList<CgroupPlacement> _attributionFailures = [];
    private LayerSyncResult? _layerSync;

    /// <summary>Coverage statement of the connect-time layer (docs/LINUX_EBPF.md §3): never advertised wider than it is.</summary>
    public const string BpfCoverageStatement =
        "BPF connect-time coverage: unscoped outbound block rules only; scoped (address/port), inbound and allow rules are enforced by nftables alone with the ~1 s exec window.";

    /// <summary>Limitation every Linux build carries: the attribution loop is periodic.</summary>
    public const string ExecRaceLimitation =
        "Attribution is a 1 s loop: a process that connects within ~1 s of exec is not blocked until it is herded into its app cgroup.";

    /// <summary>Limitation while no connect-time layer is active (docs/LINUX_EBPF.md).</summary>
    public const string BpfLayerInactiveLimitation =
        "BPF layer inactive: connect-time verdicts are not enforced; nftables (socket cgroupv2) is the only boundary.";

    public NftFirewallPolicyAdapter(NftEnginePaths paths, NftTable table, AppCgroupManager cgroups, IFilterEventSink events)
        : this(paths, table, cgroups, events, () => FirewallWriteGate.IsOpen, TimeProvider.System)
    {
    }

    public NftFirewallPolicyAdapter(
        NftEnginePaths paths,
        NftTable table,
        AppCgroupManager cgroups,
        IFilterEventSink events,
        Func<bool> writeGate,
        TimeProvider time)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _table = table ?? throw new ArgumentNullException(nameof(table));
        _cgroups = cgroups ?? throw new ArgumentNullException(nameof(cgroups));
        _events = events ?? throw new ArgumentNullException(nameof(events));
        _writeGate = writeGate ?? throw new ArgumentNullException(nameof(writeGate));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <summary>Outcome of the last publish in the IPC contract shape; null before the first publish.</summary>
    public FilterEnforcementReport? Enforcement
    {
        get
        {
            lock (_reportGate)
            {
                return _enforcement;
            }
        }
    }

    /// <summary>The cgroup manager, for the attribution loop and the trace monitor's fallback.</summary>
    public AppCgroupManager Cgroups => _cgroups;

    /// <summary>
    /// Optional connect-time layer (the BPF engine, docs/LINUX_EBPF.md) synced after every
    /// successful publish with the same rules and generation; null or inactive = nft only.
    /// </summary>
    public IVerdictLayer? VerdictLayer { get; set; }

    public void Dispose() => _gate.Dispose();

    public async Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        if (!TryProbeWritable(out var problem))
        {
            return new FirewallCapabilityReport
            {
                Status = FirewallCapabilityStatus.Unavailable,
                Reason = $"The Axiom state directory {_paths.FilterDirectory} is not writable ({problem}). " +
                         "Firewall rules need the root axiomd systemd service.",
                FirewallServiceRunning = false,
                ManagedRulesReadable = false,
                ManagedRuleCount = null,
                ProbedUtc = now,
                Limitations = Limitations(),
            };
        }

        var state = LoadState();
        var enforcement = await RefreshAsync(ct).ConfigureAwait(false);
        var reason = enforcement.State switch
        {
            FilterEnforcementState.Unavailable => "table inet axiom has not been published yet; rules are stored but not enforced.",
            FilterEnforcementState.Degraded when enforcement.FileError is { Length: > 0 } error =>
                $"nftables rejected the last Axiom table ({error}); the previous generation stays in force.",
            FilterEnforcementState.Degraded when !enforcement.Connected && _nftError is { } nftError =>
                $"nftables is unavailable ({nftError}); rules are stored but not known to be enforced.",
            FilterEnforcementState.Degraded when !enforcement.Connected => MissingTableReason(),
            FilterEnforcementState.Degraded when _tableIntegrity is { Modified: true } integrity => string.Create(
                CultureInfo.InvariantCulture,
                $"nft table inet axiom modified externally: generation {enforcement.AckedGeneration} is present but {integrity.Missing} of {integrity.Expected} owned rule(s) are missing (another tool flushed the table or deleted rules); those rules are not enforced by nftables until the daemon republishes the table (next watch tick)."),
            FilterEnforcementState.Degraded => string.Create(
                CultureInfo.InvariantCulture,
                $"table inet axiom is present (generation {enforcement.AckedGeneration}) and nftables enforces the stored rules; enforcement is degraded by the connect-time BPF layer:"),
            FilterEnforcementState.Pending => string.Create(
                CultureInfo.InvariantCulture,
                $"nftables holds generation {enforcement.AckedGeneration?.ToString(CultureInfo.InvariantCulture) ?? "none"}; generation {enforcement.PublishedGeneration} is pending."),
            _ => null,
        };

        var layerSync = LayerSync;
        if (VerdictLayer is { StaleProgramsAttached: true } staleLayer)
        {
            var note = $"BPF programs of a previous daemon are still attached and could not be detached ({staleLayer.Status}); removed rules may still block at connect time. The daemon retries every watch tick.";
            reason = reason is null ? note : reason + " " + note;
        }

        if (state.PendingRemovals.Count > 0)
        {
            var note = string.Create(CultureInfo.InvariantCulture, $"{state.PendingRemovals.Count} rule removal(s) whose BPF verdict cleanup is not confirmed ({string.Join(", ", state.PendingRemovals.Select(removal => $"{removal.RuleId:D} {removal.AppPath}: {removal.Reason}"))}).");
            reason = reason is null ? note : reason + " " + note;
        }

        if (layerSync is { StaleEntriesCanBlock: true })
        {
            var note = string.Create(CultureInfo.InvariantCulture, $"BPF verdict maps hold {layerSync.FailedDeletes.Count} stale entr{(layerSync.FailedDeletes.Count == 1 ? "y" : "ies")} that could not be deleted and the programs could not be detached: removed rules may still block at connect time ({string.Join("; ", layerSync.FailedDeletes)}).");
            reason = reason is null ? note : reason + " " + note;
        }
        else if (layerSync is { Neutralised: true })
        {
            var note = $"BPF layer neutralised ({VerdictLayer?.Status}); nftables alone enforces until the daemon re-attaches it (watch tick).";
            reason = reason is null ? note : reason + " " + note;
        }
        else if (layerSync is { Attached: true, Applied: false })
        {
            var note = string.Create(CultureInfo.InvariantCulture, $"BPF map sync for generation {layerSync.Generation} is incomplete ({layerSync.FailedUpdates.Count} update(s) failed after {layerSync.Attempts} pass(es)); affected rules are enforced by nftables alone until the next publish succeeds.");
            reason = reason is null ? note : reason + " " + note;
        }
        else if (VerdictLayer is { Active: false } layer && enforcement.State != FilterEnforcementState.Unavailable)
        {
            // Still Available: nftables enforces every rule; only the exec-time race window is open.
            var note = $"Connect-time BPF layer {layer.Status}; a process that connects within ~1 s of exec is not blocked until herded.";
            reason = reason is null ? note : reason + " " + note;
        }

        return new FirewallCapabilityReport
        {
            // Pending (table holds another generation for a moment) stays Available with a reason, as on macOS;
            // Degraded is the lost/foreign table, unreadable nft, a rejected batch, or a BPF layer that holds
            // stale verdicts / had to be neutralised (LNX-1).
            Status = enforcement.State == FilterEnforcementState.Degraded ? FirewallCapabilityStatus.Degraded : FirewallCapabilityStatus.Available,
            Reason = reason,
            FirewallServiceRunning = enforcement.Connected,
            ManagedRulesReadable = true,
            ManagedRuleCount = state.Rules.Count,
            ProbedUtc = now,
            FilterEnforcement = enforcement,
            Limitations = Limitations(),
            ConnectTimeLayer = DescribeConnectTimeLayer(state.Rules),
        };
    }

    /// <summary>
    /// Whether a connect-time verdict layer (docs/LINUX_EBPF.md) is attached right now; false =
    /// nftables is the only boundary and the exec race is open.
    /// </summary>
    public bool ConnectTimeLayerActive => VerdictLayer is { Active: true };

    /// <summary>Outcome of the last BPF map sync (null before the first or without a layer); part of the effective state.</summary>
    public LayerSyncResult? LayerSync
    {
        get
        {
            lock (_reportGate)
            {
                return _layerSync;
            }
        }
    }

    /// <summary>Limitations of this enforcement build (shown with the capability report).</summary>
    public IReadOnlyList<string> Limitations()
    {
        var lines = new List<string>();
        var sync = LayerSync;
        if (ConnectTimeLayerActive)
        {
            lines.Add(ExecRaceLimitation + " The BPF layer closes this window for unscoped outbound block rules.");
            lines.Add(BpfCoverageStatement);
        }
        else if (VerdictLayer is { } layer)
        {
            lines.Add(ExecRaceLimitation);
            lines.Add(layer.Neutralised
                ? $"BPF layer neutralised ({layer.Status}): the daemon detached its own programs after a stale verdict could not be deleted; nftables (socket cgroupv2) is the only boundary until it re-attaches."
                : $"BPF layer inactive ({layer.Status}): connect-time verdicts are not enforced; nftables (socket cgroupv2) is the only boundary.");
        }
        else
        {
            lines.Add(ExecRaceLimitation);
            lines.Add(BpfLayerInactiveLimitation);
        }

        var nftOnly = LoadState().Rules.Count(rule => rule.Spec.Enabled && CoverageOf(rule.Spec).Proven != true);
        if (nftOnly > 0)
        {
            lines.Add(string.Create(CultureInfo.InvariantCulture, $"{nftOnly} rule(s) are nft-only: {NftOnlyStatement}. Only rules marked connect-time proven refuse a new process at connect()."));
        }

        if (sync is { StaleEntriesCanBlock: true })
        {
            lines.Add(string.Create(CultureInfo.InvariantCulture, $"BPF map sync failed: {sync.FailedDeletes.Count} stale verdict(s) still attached after {sync.Attempts} pass(es) ({string.Join("; ", sync.FailedDeletes)}); removed rules may still block at connect time."));
        }
        else if (sync is { Attached: true, Applied: false })
        {
            lines.Add(string.Create(CultureInfo.InvariantCulture, $"BPF map sync failed for generation {sync.Generation}: {sync.FailedUpdates.Count} update(s) not written after {sync.Attempts} pass(es) ({string.Join("; ", sync.FailedUpdates)}); those rules are enforced by nftables alone."));
        }

        return lines;
    }

    private string? _nftError;

    /// <summary>
    /// Reads the live table (<c>nft -j list table inet axiom</c>) and rebuilds the enforcement report
    /// from it: <c>Connected</c> = the table with Axiom's comment exists now, <c>AckedGeneration</c> =
    /// the generation it carries, state per <see cref="Evaluate"/>. Never throws; an nft failure
    /// is a degraded report with the error kept for the capability reason.
    /// </summary>
    public async Task<FilterEnforcementReport> RefreshAsync(CancellationToken ct)
    {
        var readback = await ReadbackAsync(ct).ConfigureAwait(false);
        return Rebuild(readback);
    }

    /// <summary>The watcher found the table gone (or foreign): degrade immediately, before republishing.</summary>
    public async Task<FilterEnforcementReport> MarkTableLostAsync(CancellationToken ct) => await RefreshAsync(ct).ConfigureAwait(false);

    private sealed record Readback(long? Generation, IReadOnlyList<NftRuleCounter> Counters, string? NftError, DateTimeOffset At);

    /// <summary>
    /// Owned-rule integrity of the published generation: <see cref="Expected"/> rule comments were applied,
    /// <see cref="Missing"/> of them are absent now. <see cref="Modified"/> only when the first readback after
    /// the publish held all of them (an nft that never prints comments must not cause a republish loop).
    /// </summary>
    private sealed record TableIntegrity(long Generation, int Expected, int Missing, bool BaselineComplete)
    {
        public bool Modified => BaselineComplete && Missing > 0;
    }

    private HashSet<(Guid RuleId, int Part)> _publishedRuleKeys = [];
    private TableIntegrity? _tableIntegrity;

    private static readonly System.Text.RegularExpressions.Regex RuleCommentPattern =
        new("comment \"(axiom:[0-9a-fA-F-]+:[0-9]+)\"", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static HashSet<(Guid RuleId, int Part)> RuleKeys(string script)
    {
        var keys = new HashSet<(Guid, int)>();
        foreach (System.Text.RegularExpressions.Match match in RuleCommentPattern.Matches(script))
        {
            if (NftTable.TryParseComment(match.Groups[1].Value, out var ruleId, out var part))
            {
                keys.Add((ruleId, part));
            }
        }

        return keys;
    }

    /// <summary>
    /// True when <c>table inet axiom</c> carries the published generation but owned rules are missing
    /// (<c>nft flush table inet axiom</c>, a deleted rule): the watcher republishes it. Pure over <paramref name="json"/>.
    /// </summary>
    public bool OwnedRulesMissing(string? json)
    {
        var generation = NftTable.ParseGeneration(json);
        TrackIntegrity(generation, generation is null ? [] : NftTable.ParseCounters(json));
        lock (_reportGate)
        {
            return generation is not null && _tableIntegrity is { Modified: true } integrity && integrity.Generation == generation;
        }
    }

    /// <summary>Owned rules the published generation carries vs. how many are missing now (for the watcher's log).</summary>
    public (int Expected, int Missing) OwnedRuleIntegrity
    {
        get
        {
            lock (_reportGate)
            {
                return _tableIntegrity is { } integrity ? (integrity.Expected, integrity.Missing) : (_publishedRuleKeys.Count, 0);
            }
        }
    }

    /// <summary>Missing-table reason (the table is gone or foreign while nft itself is readable).</summary>
    private string MissingTableReason()
    {
        var reason = "nft table inet axiom missing (removed externally: another tool deleted it or flushed the ruleset); the stored rules are not enforced by nftables until the daemon restores the table (next watch tick).";
        return VerdictLayer is { Active: true }
            ? reason + " The connect-time BPF layer is still attached and keeps refusing its connect-time proven rules meanwhile."
            : reason;
    }

    private void TrackIntegrity(long? generation, IReadOnlyList<NftRuleCounter> counters)
    {
        lock (_reportGate)
        {
            if (generation is null || generation != _published)
            {
                return;
            }

            var present = counters.Select(counter => (counter.RuleId, counter.Part)).ToHashSet();
            var missing = _publishedRuleKeys.Count(key => !present.Contains(key));
            var baseline = _tableIntegrity is { } previous && previous.Generation == generation
                ? previous.BaselineComplete
                : missing == 0;
            _tableIntegrity = new TableIntegrity(generation.Value, _publishedRuleKeys.Count, missing, baseline);
        }
    }

    private async Task<Readback> ReadbackAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        try
        {
            var json = await _table.ListJsonAsync(ct).ConfigureAwait(false);
            var generation = NftTable.ParseGeneration(json);
            _nftError = null;
            if (generation is not null)
            {
                _lastSeenUtc = now;
                if (generation == _published)
                {
                    _lastAckUtc = now;
                }
            }

            var counters = generation is null ? [] : NftTable.ParseCounters(json);
            TrackIntegrity(generation, counters);
            return new Readback(generation, counters, null, now);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _nftError = exception.Message;
            return new Readback(null, [], exception.Message, now);
        }
    }

    /// <summary>
    /// Pure state of the published generation given what nftables holds right now:
    /// <see cref="FilterEnforcementState.Unavailable"/> before the first publish,
    /// <see cref="FilterEnforcementState.Degraded"/> when nft cannot be read, the table is absent or
    /// foreign, or the last batch was rejected, <see cref="FilterEnforcementState.Pending"/> when the
    /// table holds another generation than the one published, else <see cref="FilterEnforcementState.Verified"/>.
    /// </summary>
    public static FilterEnforcementState Evaluate(long published, long? live, bool nftReadable, bool fileRejected)
    {
        if (published < 0)
        {
            return FilterEnforcementState.Unavailable;
        }

        if (!nftReadable || live is null || fileRejected)
        {
            return FilterEnforcementState.Degraded;
        }

        return live == published ? FilterEnforcementState.Verified : FilterEnforcementState.Pending;
    }

    /// <summary>
    /// <see cref="Evaluate(long, long?, bool, bool)"/> folded with the connect-time layer (LNX-1):
    /// a stale verdict that still enforces, or a layer that had to detach itself, is
    /// <see cref="FilterEnforcementState.Degraded"/>; an attached layer whose maps miss entries is
    /// <see cref="FilterEnforcementState.Pending"/>. A layer that never attached (no BTF, no root)
    /// does not degrade anything: nftables is then the whole, verified boundary.
    /// </summary>
    public static FilterEnforcementState Evaluate(long published, long? live, bool nftReadable, bool fileRejected, LayerSyncResult? layer)
    {
        var state = Evaluate(published, live, nftReadable, fileRejected);
        if (state is FilterEnforcementState.Unavailable or FilterEnforcementState.Degraded || layer is null)
        {
            return state;
        }

        if (layer.StaleEntriesCanBlock || layer.Neutralised)
        {
            return FilterEnforcementState.Degraded;
        }

        return layer is { Attached: true, Applied: false } ? FilterEnforcementState.Pending : state;
    }

    private FilterEnforcementReport Rebuild(Readback readback)
    {
        lock (_reportGate)
        {
            var previous = _enforcement;
            var fileRejected = previous?.FileError is { Length: > 0 };
            var state = Evaluate(_published, readback.Generation, readback.NftError is null, fileRejected, _layerSync);
            if (state is FilterEnforcementState.Verified or FilterEnforcementState.Pending
                && (VerdictLayer is { StaleProgramsAttached: true } || LoadState().PendingRemovals.Count > 0))
            {
                // A stale program set or an unconfirmed BPF removal can still block what nft no longer does.
                state = FilterEnforcementState.Degraded;
            }

            if (state is FilterEnforcementState.Verified or FilterEnforcementState.Pending
                && _tableIntegrity is { Modified: true } integrity && integrity.Generation == readback.Generation)
            {
                // The generation comment survived but owned rules did not (nft flush table inet axiom).
                state = FilterEnforcementState.Degraded;
            }

            var report = new FilterEnforcementReport
            {
                State = state,
                Connected = readback.NftError is null && readback.Generation is not null,
                PublishedGeneration = _published,
                AckedGeneration = readback.Generation,
                LastSeenUtc = _lastSeenUtc,
                LastAckUtc = _lastAckUtc,
                Generation = previous?.Generation ?? -1,
                AppliedRuleCount = state == FilterEnforcementState.Verified ? previous?.AppliedRuleCount ?? 0 : 0,
                RejectedRules = previous?.RejectedRules ?? [],
                FileError = previous?.FileError,
                DroppedEvents = 0,
                ReportedUtc = readback.At,
            };
            _enforcement = report;
            return report;
        }
    }

    /// <summary>
    /// Owned rules projected through the last enforcement report: <see cref="RuleState.Applied"/>
    /// only while the published generation is verified and the rule is neither refused by the
    /// compiler nor waiting for a live process to be herded; refused rules are
    /// <see cref="RuleState.Failed"/>; everything else is <see cref="RuleState.Pending"/>.
    /// </summary>
    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var report = Enforcement;
        var compilation = _lastCompilation;
        var layerFailed = LayerSync is { Attached: true } sync ? sync.FailedRuleIds.ToHashSet() : [];
        return Task.FromResult<IReadOnlyList<ManagedRule>>(
            LoadState().Rules.Select(rule =>
            {
                var coverage = CoverageOf(rule.Spec);
                return rule with
                {
                    State = layerFailed.Contains(rule.ManagedRuleId) && rule.State != RuleState.Failed ? RuleState.Pending : ProjectState(rule, report, compilation),
                    ConnectTimeBlockingProven = coverage.Proven,
                    CoverageReason = coverage.Reason,
                };
            }).ToList());
    }

    /// <summary>Pure projection of one stored rule under the current report (see <see cref="ListOwnedRulesAsync"/>).</summary>
    public static RuleState ProjectState(ManagedRule rule, FilterEnforcementReport? report, NftCompilation? compilation)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (compilation is not null && compilation.Rejected.Any(rejected => rejected.RuleId == rule.ManagedRuleId))
        {
            return RuleState.Failed;
        }

        if (report is null || report.State != FilterEnforcementState.Verified)
        {
            return rule.State == RuleState.Failed ? RuleState.Failed : RuleState.Pending;
        }

        var id = rule.ManagedRuleId.ToString("D", CultureInfo.InvariantCulture);
        return report.RejectedRules.Any(rejected => string.Equals(rejected.RuleId, id, StringComparison.OrdinalIgnoreCase))
            ? RuleState.Pending
            : RuleState.Applied;
    }

    public async Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        EnsureWriteGate();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var state = LoadState();
            var rule = new ManagedRule
            {
                ManagedRuleId = spec.ManagedRuleId,
                OsRuleName = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction),
                OwnershipGroup = OwnedRuleOwnership.GroupName,
                Spec = spec,
                State = RuleState.Pending,
                LastVerifiedUtc = null,
            };
            var rules = state.Rules.Where(existing => existing.ManagedRuleId != spec.ManagedRuleId).Append(rule).ToList();
            var outcome = await PublishAsync(rules, state.Generation, ct).ConfigureAwait(false);
            if (outcome.Error is { } error)
            {
                return Failed(spec.ManagedRuleId, "nft.apply_failed", error) with { OsRuleName = rule.OsRuleName };
            }

            // The batch is in the kernel. Applied needs the readback and the cgroup, nothing less.
            var readback = await ReadbackAsync(ct).ConfigureAwait(false);
            var report = Rebuild(readback);
            var result = Outcome(spec, rule.OsRuleName, outcome.Compilation, readback.Generation, readback.Counters, report, CgroupPresent(outcome.Compilation, spec.ManagedRuleId), _attributionFailures, LayerSync);
            if (result.Success)
            {
                var coverage = CoverageOf(spec);
                result = result with { ConnectTimeBlockingProven = coverage.Proven, CoverageReason = coverage.Reason };
            }

            SaveState(LoadState() with
            {
                Generation = outcome.Compilation.Generation,
                Rules = rules.Select(candidate => candidate.ManagedRuleId == spec.ManagedRuleId
                    ? candidate with { State = result.State, LastVerifiedUtc = result.VerifiedUtc, LastErrorCode = result.ErrorCode }
                    : candidate).ToList(),
            });
            return result;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Failed(spec.ManagedRuleId, "filter.write_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Pure lifecycle decision after a successful batch (docs/LINUX_ARCHITECTURE.md, rule lifecycle):
    /// a rule the compiler refused is <see cref="RuleState.Failed"/> (<c>nft.rule_rejected</c>); the
    /// rule is <see cref="RuleState.Applied"/> only when the table read back holds exactly the
    /// published generation, carries the rule's comment, the app cgroup exists and no live process
    /// of the app failed to be herded; any other combination is <see cref="RuleState.Pending"/>
    /// with the reason (<c>nft.readback_mismatch</c> / <c>nft.cgroup_missing</c> / <c>nft.attribution_failed</c>).
    /// A disabled rule has no nft lines and is Applied once the generation is verified.
    /// With a connect-time layer (LNX-1): a stale verdict that still enforces is <c>bpf.stale_entry</c>,
    /// a map update of this rule that failed is <c>bpf.update_failed</c>, a layer that had to detach
    /// itself is <c>bpf.neutralised</c> — all <see cref="RuleState.Pending"/>, never Applied.
    /// </summary>
    public static RuleApplyResult Outcome(
        RuleSpec spec,
        string? osRuleName,
        NftCompilation compilation,
        long? liveGeneration,
        IReadOnlyList<NftRuleCounter> counters,
        FilterEnforcementReport report,
        bool cgroupExists,
        IReadOnlyList<CgroupPlacement> attributionFailures,
        LayerSyncResult? layer = null)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(compilation);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(attributionFailures);

        if (compilation.Rejected.FirstOrDefault(rejected => rejected.RuleId == spec.ManagedRuleId) is { } refused)
        {
            return Failed(spec.ManagedRuleId, "nft.rule_rejected", $"nftables does not enforce this rule: {refused.Reason}") with { OsRuleName = osRuleName };
        }

        string? pendingCode = null;
        string? pendingWhy = null;
        if (liveGeneration != compilation.Generation)
        {
            pendingCode = "nft.readback_mismatch";
            pendingWhy = liveGeneration is null
                ? "table inet axiom is not present after the apply"
                : string.Create(CultureInfo.InvariantCulture, $"table inet axiom holds generation {liveGeneration}, not {compilation.Generation}");
        }
        else if (spec.Enabled && compilation.Applied.Any(applied => applied.RuleId == spec.ManagedRuleId) && counters.All(counter => counter.RuleId != spec.ManagedRuleId))
        {
            pendingCode = "nft.readback_mismatch";
            pendingWhy = string.Create(CultureInfo.InvariantCulture, $"generation {compilation.Generation} read back without the rule's comment");
        }
        else if (spec.Enabled && !cgroupExists)
        {
            pendingCode = "nft.cgroup_missing";
            pendingWhy = "the app cgroup does not exist";
        }
        else if (attributionFailures.FirstOrDefault(failure => compilation.Applied.Any(applied => applied.RuleId == spec.ManagedRuleId && applied.CgroupPath == failure.TargetCgroup)) is { } failure)
        {
            pendingCode = "nft.attribution_failed";
            pendingWhy = string.Create(CultureInfo.InvariantCulture, $"live process pid {failure.Pid} ({failure.ExePath}) could not be moved into {failure.TargetCgroup}: {failure.Error}");
        }
        else if (layer is { StaleEntriesCanBlock: true })
        {
            pendingCode = "bpf.stale_entry";
            pendingWhy = string.Create(CultureInfo.InvariantCulture, $"the BPF verdict maps still hold {layer.FailedDeletes.Count} stale entr{(layer.FailedDeletes.Count == 1 ? "y" : "ies")} that could not be deleted ({string.Join("; ", layer.FailedDeletes)}) and the programs could not be detached; connect-time verdicts are not the published rule set");
        }
        else if (layer is { Neutralised: true })
        {
            pendingCode = "bpf.neutralised";
            pendingWhy = "the BPF layer detached itself after a stale verdict could not be deleted; nftables enforces this rule alone until the daemon re-attaches the layer";
        }
        else if (layer is { Attached: true, Applied: false } && spec.Enabled && (layer.FailedUpdates.Any(failure => failure.RuleId == spec.ManagedRuleId || failure.RuleId is null) || layer.CoveredRules.Contains(spec.ManagedRuleId)))
        {
            var mine = layer.FailedUpdates.Where(failure => failure.RuleId == spec.ManagedRuleId || failure.RuleId is null).ToList();
            if (mine.Count > 0)
            {
                pendingCode = "bpf.update_failed";
                pendingWhy = string.Create(CultureInfo.InvariantCulture, $"BPF map update failed after {layer.Attempts} pass(es) ({string.Join("; ", mine)}); nftables enforces the rule, the connect-time verdict is missing");
            }
        }

        if (pendingCode is not null)
        {
            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = spec.ManagedRuleId,
                State = RuleState.Pending,
                OsRuleName = osRuleName,
                ErrorCode = pendingCode,
                ErrorMessage = string.Create(CultureInfo.InvariantCulture, $"published generation {compilation.Generation}; not verified: {pendingWhy}"),
            };
        }

        return new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = spec.ManagedRuleId,
            State = RuleState.Applied,
            OsRuleName = osRuleName,
            VerifiedUtc = report.LastAckUtc ?? report.ReportedUtc,
        };
    }

    /// <summary>Persists a removal whose BPF cleanup is unconfirmed (survives a daemon restart).</summary>
    private void RecordPendingRemoval(ManagedRule? existing, Guid ruleId, long generation, string reason)
    {
        var state = LoadState();
        var pending = state.PendingRemovals.Where(removal => removal.RuleId != ruleId).Append(new PendingRemoval(ruleId, existing?.Spec.AppPath ?? string.Empty, generation, reason, _time.GetUtcNow())).ToList();
        SaveState(state with { PendingRemovals = pending });
    }

    /// <summary>
    /// Pending removals are confirmed only by an attached layer whose maps were written and read
    /// back equal to the plan (which no longer holds them) with no stale program set left.
    /// </summary>
    private void ClearPendingRemovalsIfConfirmed(LayerSyncResult sync)
    {
        if (sync is not { Attached: true, Applied: true, Verified: true } || VerdictLayer is { StaleProgramsAttached: true })
        {
            return;
        }

        var state = LoadState();
        if (state.PendingRemovals.Count > 0)
        {
            SaveState(state with { PendingRemovals = [] });
        }
    }

    /// <summary>Removed rules whose BPF cleanup is not confirmed (from managed-rules.json).</summary>
    public IReadOnlyList<PendingRemoval> PendingRemovals => LoadState().PendingRemovals;

    /// <summary>Statement attached to every nft-only rule (PR #276 round 3).</summary>
    public const string NftOnlyStatement =
        "nft rule installed/read back, not race-free: a newly launched process can connect during the ~1 s cgroup attribution window before it is herded";

    /// <summary>
    /// Per-rule coverage (PR #276 round 3): true only when the connect-time layer is attached, healthy,
    /// and its last sync wrote and read back a verdict for this rule; otherwise the rule is nft-only and
    /// the reason says why. Null for disabled rules.
    /// </summary>
    public static (bool? Proven, string? Reason) Coverage(RuleSpec spec, IVerdictLayer? layer, LayerSyncResult? sync, IReadOnlyCollection<Guid>? staleExeKeys = null)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!spec.Enabled)
        {
            return (null, null);
        }

        string why;
        if (layer is null)
        {
            why = "no connect-time layer is configured";
        }
        else if (layer.StaleProgramsAttached)
        {
            why = "the BPF layer is not loaded: a previous daemon's programs could not be detached";
        }
        else if (layer.Neutralised)
        {
            why = $"the BPF layer is neutralised ({layer.Status})";
        }
        else if (!layer.Active)
        {
            why = $"the BPF layer is inactive ({layer.Status})";
        }
        else if (sync is null)
        {
            why = "the BPF maps have not been synced yet";
        }
        else if (sync.FailedUpdates.Any(failure => failure.RuleId == spec.ManagedRuleId))
        {
            why = "the BPF map update for this rule failed";
        }
        else if (sync.StaleEntriesCanBlock)
        {
            why = "the BPF maps hold stale entries; the layer is not trusted";
        }
        else if (staleExeKeys?.Contains(spec.ManagedRuleId) == true)
        {
            why = "the executable at this path was replaced (new inode) since its connect-time key was written; the daemon re-resolves it on the next watch tick";
        }
        else if (sync.CoveredRules.Contains(spec.ManagedRuleId))
        {
            return sync is { Attached: true, Applied: true, Verified: true }
                ? (true, string.Create(CultureInfo.InvariantCulture, $"connect-time verdict attached and read back (BPF generation {sync.Generation}); a new process is refused at connect()"))
                : (false, $"BPF verdict written but not read back; {NftOnlyStatement}");
        }
        else if (sync.Uncovered.FirstOrDefault(rule => rule.RuleId == spec.ManagedRuleId) is { } uncovered)
        {
            why = uncovered.Reason;
        }
        else if (spec.Direction != FirewallDirection.Outbound || spec.Action != FirewallAction.Block || (spec.RemoteAddresses?.Count ?? 0) > 0 || !string.IsNullOrWhiteSpace(spec.RemotePorts))
        {
            why = "scoped (address/port/protocol), inbound and allow rules are not expressed by the BPF layer";
        }
        else
        {
            why = "the BPF layer does not express this rule";
        }

        return (false, $"{why}; {NftOnlyStatement}");
    }

    private (bool? Proven, string? Reason) CoverageOf(RuleSpec spec) => Coverage(spec, VerdictLayer, LayerSync);

    /// <summary>Rules whose executable was replaced since the last layer sync (re-resolved by the watch tick).</summary>
    public IReadOnlyList<Guid> StaleExeKeyRules() => VerdictLayer is { Active: true } layer ? layer.StaleExeKeys(LoadState().Rules) : [];

    /// <summary>Live connect-time layer state for the capability report (and <c>--doctor</c> over IPC).</summary>
    public ConnectTimeLayerReport DescribeConnectTimeLayer(IReadOnlyList<ManagedRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var sync = LayerSync;
        var pending = PendingRemovals.Select(removal => removal.RuleId).ToList();
        var enabled = rules.Where(rule => rule.Spec.Enabled).ToList();
        var proven = enabled.Where(rule => CoverageOf(rule.Spec).Proven == true).Select(rule => rule.ManagedRuleId).ToList();
        var nftOnly = enabled.Where(rule => CoverageOf(rule.Spec).Proven != true).Select(rule => rule.ManagedRuleId).ToList();
        if (VerdictLayer is not { } layer)
        {
            return new ConnectTimeLayerReport { State = "not_configured", Healthy = false, Status = "no connect-time layer configured", NftOnlyRules = nftOnly, PendingRemovals = pending };
        }

        var state = layer.StaleProgramsAttached ? "stale_programs"
            : sync is { StaleEntriesCanBlock: true } ? "degraded"
            : layer.Neutralised ? "neutralised"
            : layer.Active ? "active"
            : "inactive";
        var healthy = state == "active" && pending.Count == 0 && (sync is null || (sync.Applied && sync.Verified && sync.FailedDeletes.Count == 0 && sync.FailedUpdates.Count == 0));
        return new ConnectTimeLayerReport
        {
            State = state,
            Healthy = healthy,
            Attached = layer.Active || layer.StaleProgramsAttached || sync is { StaleEntriesCanBlock: true },
            Status = layer.Status,
            Generation = sync?.Generation,
            MapsVerified = sync is { Verified: true },
            ConnectTimeProvenRules = proven,
            NftOnlyRules = nftOnly,
            PendingRemovals = pending,
            FailedDeletes = sync?.FailedDeletes.Select(failure => failure.ToString()).ToList() ?? [],
            FailedUpdates = sync?.FailedUpdates.Select(failure => failure.ToString()).ToList() ?? [],
        };
    }

    private bool CgroupPresent(NftCompilation compilation, Guid ruleId)
    {
        var compiled = compilation.Applied.FirstOrDefault(applied => applied.RuleId == ruleId);
        return compiled is not null && _cgroups.Exists(compiled.CgroupPath);
    }

    public async Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        EnsureWriteGate();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var state = LoadState();
            var existing = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
            var rules = state.Rules.Where(rule => rule.ManagedRuleId != managedRuleId).ToList();
            var outcome = await PublishAsync(rules, state.Generation, ct).ConfigureAwait(false);
            if (outcome.Error is { } error)
            {
                return Failed(managedRuleId, "nft.apply_failed", error);
            }

            // Gone from the batch; verified gone only when the readback shows the new generation without it
            // AND no attached layer still holds a verdict for it (LNX-1): a stale BPF entry keeps blocking.
            var readback = await ReadbackAsync(ct).ConfigureAwait(false);
            var report = Rebuild(readback);
            var layer = LayerSync;
            var nftVerified = Evaluate(_published, readback.Generation, readback.NftError is null, report.FileError is { Length: > 0 }) == FilterEnforcementState.Verified && readback.Counters.All(counter => counter.RuleId != managedRuleId);
            if (layer is { StaleEntriesCanBlock: true } || layer is { Neutralised: true, FailedDeletes.Count: > 0 })
            {
                var stale = layer.FailedDeletes.Count > 0 ? string.Join("; ", layer.FailedDeletes) : "(no detail)";
                var neutralised = layer.Neutralised;
                RecordPendingRemoval(existing, managedRuleId, outcome.Compilation.Generation, neutralised ? "bpf.delete_failed" : "bpf.stale_entry: " + stale);
                return new RuleApplyResult
                {
                    Success = false,
                    ManagedRuleId = managedRuleId,
                    State = RuleState.Pending,
                    OsRuleName = existing?.OsRuleName,
                    ErrorCode = neutralised ? "bpf.delete_failed" : "bpf.stale_entry",
                    ErrorMessage = neutralised
                        ? string.Create(CultureInfo.InvariantCulture, $"removed from nftables (generation {outcome.Compilation.Generation}), but the BPF verdict entry could not be deleted after {layer.Attempts} pass(es) ({stale}); the daemon detached its own BPF programs so the stale entry cannot block, and re-attaches them on its next watch tick. Retry rule.remove to confirm; nothing of this rule enforces now.")
                        : string.Create(CultureInfo.InvariantCulture, $"removed from nftables (generation {outcome.Compilation.Generation}), but the BPF verdict entry could not be deleted after {layer.Attempts} pass(es) ({stale}) and the BPF programs could not be detached: the app may still be blocked at connect time. Retry rule.remove; if it persists, restart axiomd (the start reconciles the maps) or run `bpftool map delete` on /sys/fs/bpf/axiom/maps."),
                };
            }

            // An attached layer must have written AND read back the plan; a layer that is detached (never
            // attached, or detached by another tool) cannot enforce the removed rule.
            var verified = nftVerified && (layer is null || !layer.Attached || (layer.Applied && layer.Verified));
            if (VerdictLayer is { StaleProgramsAttached: true })
            {
                RecordPendingRemoval(existing, managedRuleId, outcome.Compilation.Generation, "a previous daemon's BPF programs are still attached");
                return new RuleApplyResult
                {
                    Success = false,
                    ManagedRuleId = managedRuleId,
                    State = RuleState.Pending,
                    OsRuleName = existing?.OsRuleName,
                    ErrorCode = "bpf.stale_programs",
                    ErrorMessage = string.Create(CultureInfo.InvariantCulture, $"removed from nftables (generation {outcome.Compilation.Generation}), but BPF programs of a previous daemon are still attached and could not be detached ({VerdictLayer.Status}); a stale connect-time verdict may still block the app. The daemon retries the detach on every watch tick."),
                };
            }
            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                OsRuleName = existing?.OsRuleName,
                VerifiedUtc = verified ? readback.At : null,
                ErrorMessage = verified
                    ? null
                    : nftVerified
                        ? layer!.Applied
                            ? string.Create(CultureInfo.InvariantCulture, $"removed from nftables; the BPF maps of generation {outcome.Compilation.Generation} could not be read back (bpftool map dump failed), so the connect-time state is unconfirmed")
                            : string.Create(CultureInfo.InvariantCulture, $"removed from nftables; BPF map sync for generation {outcome.Compilation.Generation} is incomplete ({layer.FailedUpdates.Count} update(s) failed), other rules are affected")
                        : string.Create(CultureInfo.InvariantCulture, $"removed from the batch; generation {outcome.Compilation.Generation} not verified in nftables yet"),
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Failed(managedRuleId, "filter.write_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<OwnedRulePresence> InspectOwnedRuleAsync(Guid managedRuleId, FirewallDirection direction, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        ct.ThrowIfCancellationRequested();
        var existing = LoadState().Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
        if (existing is null)
        {
            return Task.FromResult(OwnedRulePresence.Absent);
        }

        return Task.FromResult(
            existing.Spec.Direction == direction && OwnedRuleOwnership.IsRecoverable(existing)
                ? OwnedRulePresence.Owned
                : OwnedRulePresence.ForeignOrChanged);
    }

    /// <summary>Recovery-only removal; not behind the interactive gate, refused outside root/daemon (as on macOS).</summary>
    public async Task<RuleApplyResult> RemoveCapturedOwnedRuleAsync(Guid managedRuleId, FirewallDirection direction, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        if (!ProtectionWriteConsent.IsServiceHost && !Environment.IsPrivilegedProcess)
        {
            throw new UnauthorizedAccessException(
                "Network recovery removal requires the root axiomd daemon or an administrator recovery command.");
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var state = LoadState();
            var existing = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
            if (existing is null)
            {
                return new RuleApplyResult { Success = true, ManagedRuleId = managedRuleId, State = RuleState.Desired, VerifiedUtc = _time.GetUtcNow() };
            }

            if (existing.Spec.Direction != direction || !OwnedRuleOwnership.IsRecoverable(existing))
            {
                return Failed(managedRuleId, "rule.not_owned", "The rule identity exists but its ownership metadata changed; it was not removed.");
            }

            var outcome = await PublishAsync(state.Rules.Where(rule => rule.ManagedRuleId != managedRuleId).ToList(), state.Generation, ct).ConfigureAwait(false);
            if (outcome.Error is { } error)
            {
                return Failed(managedRuleId, "nft.apply_failed", error);
            }

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                OsRuleName = existing.OsRuleName,
                VerifiedUtc = _time.GetUtcNow(),
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Failed(managedRuleId, "filter.write_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Live verification: <c>presentInOs</c> and <c>effectiveAction</c> come from the table read back
    /// now, never from <c>managed-rules.json</c>; <c>enforcementVerified</c> is true only when the
    /// read-back generation is the published one, the rule's comment is in it, the compiler did not
    /// refuse it and its app cgroup exists.
    /// </summary>
    public async Task<EffectiveRuleReport> VerifyAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ManagedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(spec));
        }

        var now = _time.GetUtcNow();
        var state = LoadState();
        var stored = state.Rules.FirstOrDefault(rule => rule.ManagedRuleId == spec.ManagedRuleId);
        var readback = await ReadbackAsync(ct).ConfigureAwait(false);
        var report = Rebuild(readback);
        var counters = readback.Counters.Where(counter => counter.RuleId == spec.ManagedRuleId).ToList();
        var notes = new List<string>
        {
            string.Create(CultureInfo.InvariantCulture, $"managed-rules.json generation {state.Generation}."),
        };
        if (readback.NftError is { } nftError)
        {
            notes.Add($"nftables could not be read ({nftError}); the rule is stored but not known to be enforced.");
        }
        else if (readback.Generation is null)
        {
            notes.Add("table inet axiom is not present; the rule is stored but not enforced.");
        }
        else
        {
            notes.Add(string.Create(CultureInfo.InvariantCulture, $"table inet axiom generation {readback.Generation}, {counters.Count} nft rule(s), {counters.Sum(counter => counter.Packets)} packet(s) matched."));
            if (readback.Generation != _published)
            {
                notes.Add(string.Create(CultureInfo.InvariantCulture, $"generation {_published} was published; nftables holds {readback.Generation}."));
            }
        }

        var matches = stored is not null && SameSpec(stored.Spec, spec);
        if (stored is null)
        {
            notes.Add("The rule is not in managed-rules.json.");
        }
        else if (!matches)
        {
            notes.Add("The stored rule differs from the given spec.");
        }

        string? rejection = null;
        if (report.FileError is { Length: > 0 } fileError)
        {
            notes.Add(string.Create(CultureInfo.InvariantCulture, $"nftables rejected the last batch ({fileError}); generation {report.Generation} stays in force."));
        }

        rejection = report.RejectedRules
            .FirstOrDefault(rejected => Guid.TryParse(rejected.RuleId, out var id) && id == spec.ManagedRuleId)
            ?.Reason;
        if (rejection is not null)
        {
            notes.Add($"The nftables engine does not enforce this rule: {rejection}");
        }

        var cgroupExists = _lastCompilation is { } compilation && CgroupPresent(compilation, spec.ManagedRuleId);
        if (stored is { Spec.Enabled: true } && rejection is null && !cgroupExists)
        {
            notes.Add("The app cgroup for this rule does not exist; its processes are not isolated.");
        }

        var present = counters.Count > 0;
        var verified = report.State == FilterEnforcementState.Verified && present && rejection is null && cgroupExists;

        // The connect-time layer is part of the effective state (LNX-1): say which layer enforces this
        // rule, and never call it verified while the layer disagrees with the table.
        var layer = LayerSync;
        if (VerdictLayer is null)
        {
            notes.Add("BPF layer: not configured; nftables (socket cgroupv2) alone enforces this rule.");
        }
        else if (layer is { StaleEntriesCanBlock: true } && layer.FailedDeletes.Any(failure => failure.RuleId == spec.ManagedRuleId))
        {
            notes.Add(string.Create(CultureInfo.InvariantCulture, $"BPF: a stale verdict for this rule is still in an attached map ({string.Join("; ", layer.FailedDeletes.Where(failure => failure.RuleId == spec.ManagedRuleId))}); the app may still be blocked at connect time although the rule is removed."));
            present = true;
            verified = false;
        }
        else if (layer is { StaleEntriesCanBlock: true })
        {
            notes.Add("BPF: stale verdicts of other rules are still attached; the layer's state is not trusted.");
            verified = false;
        }
        else if (layer is { Neutralised: true } || VerdictLayer.Neutralised)
        {
            notes.Add($"BPF layer neutralised ({VerdictLayer.Status}); nftables alone enforces until the daemon re-attaches it.");
            verified = false;
        }
        else if (!VerdictLayer.Active)
        {
            notes.Add($"BPF layer inactive ({VerdictLayer.Status}); nftables alone enforces this rule (~1 s exec window).");
        }
        else if (layer is null)
        {
            notes.Add("BPF layer attached; maps not synced yet.");
            verified = false;
        }
        else if (layer.FailedUpdates.Any(failure => failure.RuleId == spec.ManagedRuleId))
        {
            notes.Add(string.Create(CultureInfo.InvariantCulture, $"BPF: the connect-time verdict for this rule was not written ({string.Join("; ", layer.FailedUpdates.Where(failure => failure.RuleId == spec.ManagedRuleId))}); nftables alone enforces it."));
            verified = false;
        }
        else if (layer.CoveredRules.Contains(spec.ManagedRuleId))
        {
            notes.Add(string.Create(CultureInfo.InvariantCulture, $"BPF-backed: connect-time verdict for this rule in the maps (generation {layer.Generation}{(layer.Verified ? ", read back verified" : ", read-back unavailable")})."));
        }
        else if (layer.Uncovered.FirstOrDefault(rule => rule.RuleId == spec.ManagedRuleId) is { } uncovered)
        {
            notes.Add($"nft-only: {uncovered.Reason}; the ~1 s exec window applies to this rule.");
        }
        else if (stored is { Spec.Enabled: true })
        {
            notes.Add("nft-only: the BPF layer does not express this rule.");
        }

        if (!verified && stored is not null && rejection is null)
        {
            notes.Add($"Enforcement not verified: state {report.State.ToString().ToLowerInvariant()}.");
        }

        var nftReadBack = report.State is FilterEnforcementState.Verified or FilterEnforcementState.Degraded && readback.Generation == _published && counters.Count > 0 && rejection is null && cgroupExists;
        VerdictLayer?.CheckAttached();
        var coverage = stored is not null ? Coverage(stored.Spec, VerdictLayer, LayerSync, StaleExeKeyRules()) : (null, null);
        if (coverage.Proven == false && stored is { Spec.Enabled: true })
        {
            notes.Add("Coverage: " + coverage.Reason + ".");
        }
        else if (coverage.Proven == true)
        {
            notes.Add("Coverage: connect-time blocking proven: " + coverage.Reason + ".");
        }

        return new EffectiveRuleReport
        {
            ManagedRuleId = spec.ManagedRuleId,
            PresentInOs = present,
            MatchesSpec = matches,
            EffectiveAction = verified && stored is { Spec.Enabled: true } ? stored.Spec.Action : null,
            ObservedUtc = now,
            Notes = notes,
            FilterRejectionReason = rejection,
            EnforcementVerified = verified,
            NftRuleReadBack = stored is { Spec.Enabled: true } ? nftReadBack : null,
            ConnectTimeBlockingProven = coverage.Proven,
            CoverageReason = coverage.Reason,
        };
    }

    /// <summary>Republishes the table from the owned rules (daemon start, or after a foreign flush) and returns the generation.</summary>
    public async Task<long> PublishAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var state = LoadState();
            var outcome = await PublishAsync(state.Rules, state.Generation, ct).ConfigureAwait(false);
            return outcome.Compilation.Generation;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// One attribution pass (called by the daemon's 1 s loop): herds matching pids into their app
    /// cgroups and updates the rejected list when a live process of a ruled app could not be isolated.
    /// </summary>
    public AttributionReport Attribute()
    {
        var report = _cgroups.Attribute();
        var failures = report.Placements.Where(placement => !placement.Moved).ToList();
        _attributionFailures = failures;
        if (failures.Count > 0 && _lastCompilation is { } compilation)
        {
            UpdateEnforcement(compilation, null, failures);
        }

        return report;
    }

    /// <summary>
    /// Fallback attribution for a traced block when the socket owner is gone already (a rejected SYN
    /// closes fast): the rule's app path and the first process still in its cgroup (-1 when none).
    /// </summary>
    public (int Pid, string? Path)? DescribeRuleApp(Guid ruleId)
    {
        var rule = LoadState().Rules.FirstOrDefault(rule => rule.ManagedRuleId == ruleId);
        if (rule is null)
        {
            return null;
        }

        var appPath = rule.Spec.AppPath.Trim();
        if (!_cgroups.TryResolve(appPath, out var cgroupPath, out _))
        {
            return (-1, appPath);
        }

        var pids = _cgroups.ReadProcs(cgroupPath);
        return (pids.Count > 0 ? pids[0] : -1, appPath);
    }

    /// <summary>Re-keys the cgroups of every stored rule without publishing (a fresh process joining a live table).</summary>
    public IReadOnlyList<string> ReattachCgroups()
    {
        var apps = LoadState().Rules.Where(rule => rule.Spec.Enabled).Select(rule => rule.Spec.AppPath.Trim()).Distinct(StringComparer.Ordinal).ToList();
        _cgroups.Retain(apps);
        return apps.Where(app => _cgroups.TryResolve(app, out _, out _)).ToList();
    }

    /// <summary>Re-syncs the verdict layer from the stored rules without republishing (after the layer attached at start).</summary>
    public async Task ResyncLayerAsync(CancellationToken ct)
    {
        if (VerdictLayer is not { } layer)
        {
            return;
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var state = LoadState();
            if (_tableApplied)
            {
                var sync = await layer.SyncAsync(state.Rules, state.Generation, ct).ConfigureAwait(false);
                lock (_reportGate)
                {
                    _layerSync = sync;
                }

                ClearPendingRemovalsIfConfirmed(sync);

                // The report folds the layer in (Evaluate): refresh it so a re-attached layer clears Degraded.
                Rebuild(await ReadbackAsync(ct).ConfigureAwait(false));
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Deletes the table, returns herded processes and removes the Axiom cgroups (daemon stop / uninstall). Each step runs even when the other failed.</summary>
    public async Task TeardownAsync(CancellationToken ct)
    {
        Exception? first = null;
        try
        {
            await DeleteTableAsync(ct).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            first = exception;
        }

        try
        {
            ReleaseCgroups();
        }
        catch (Exception exception) when (first is null && exception is IOException or UnauthorizedAccessException)
        {
            first = exception;
        }

        ForgetPublished();
        if (first is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(first).Throw();
        }
    }

    /// <summary>Teardown step 1: <c>nft delete table inet axiom</c> (only that table).</summary>
    public async Task DeleteTableAsync(CancellationToken ct)
    {
        var deleted = await _table.DeleteAsync(ct).ConfigureAwait(false);
        if (!deleted.Success)
        {
            throw new IOException("nft delete table inet axiom failed: " + deleted.Error);
        }
    }

    /// <summary>Teardown step 2: returns herded processes and removes every <c>axiom.slice</c> app cgroup.</summary>
    public void ReleaseCgroups() => _cgroups.RemoveAll();

    /// <summary>Teardown step 3 (in-memory): nothing is published any more.</summary>
    public void ForgetPublished()
    {
        _tableApplied = false;
        _published = -1;
        lock (_reportGate)
        {
            _enforcement = null;
            _layerSync = null;
        }
    }

    /// <summary>
    /// Startup reconciliation of cgroups (LNX-2): keys the apps that have stored rules and releases the
    /// processes of every other <c>axiom.slice</c> cgroup a crashed daemon left behind, removing the
    /// empty ones. Returns what it found (for the journal). Only <c>axiom.slice</c> is ever listed.
    /// </summary>
    public IReadOnlyList<string> ReconcileCgroups()
    {
        var found = new List<string>();
        var before = _cgroups.ListSliceCgroups();
        if (before.Count == 0)
        {
            return found;
        }

        var apps = ReattachCgroups();
        var report = _cgroups.Attribute();
        found.Add(string.Create(CultureInfo.InvariantCulture, $"{before.Count} axiom.slice cgroup(s) from a previous daemon ({apps.Count} still ruled, {report.RemovedCgroups.Count} removed: {string.Join(", ", report.RemovedCgroups)})"));
        return found;
    }

    private async Task<(NftCompilation Compilation, string? Error)> PublishAsync(IReadOnlyList<ManagedRule> rules, long stateGeneration, CancellationToken ct)
    {
        var tableGeneration = await _table.ReadGenerationAsync(ct).ConfigureAwait(false) ?? 0;
        var generation = Math.Max(stateGeneration, tableGeneration) + 1;
        // Persist ownership first: a crash between the two steps leaves the next start able to
        // republish the complete table, never a table with rules the daemon no longer knows.
        var pending = LoadState().PendingRemovals;
        SaveState(new ManagedRuleState { Generation = generation, Rules = rules, PendingRemovals = pending });
        _cgroups.Retain(rules.Where(rule => rule.Spec.Enabled).Select(rule => rule.Spec.AppPath.Trim()));
        var compilation = NftRuleCompiler.Compile(rules.Select(rule => rule.Spec), generation, _cgroups);
        AtomicFile.Write(_paths.RulesFile, compilation.Script, AtomicFile.PublishedMode);
        var applied = await _table.ApplyAsync(compilation.Script, ct).ConfigureAwait(false);
        var placements = applied.Success ? _cgroups.Attribute().Placements.Where(placement => !placement.Moved).ToList() : [];
        _tableApplied = applied.Success;
        _lastCompilation = compilation;
        if (applied.Success)
        {
            lock (_reportGate)
            {
                _publishedRuleKeys = RuleKeys(compilation.Script);
                _tableIntegrity = null;
            }

            _published = generation;
            _attributionFailures = placements;
        }

        UpdateEnforcement(compilation, applied.Success ? null : applied.Error, placements);
        if (applied.Success && VerdictLayer is { } layer)
        {
            // The layer's outcome is part of the effective state (LNX-1): the callers fold it into the
            // rule result, the enforcement report and the capability reason; the nft batch itself stands.
            var sync = await layer.SyncAsync(rules, generation, ct).ConfigureAwait(false);
            lock (_reportGate)
            {
                _layerSync = sync;
            }

            ClearPendingRemovalsIfConfirmed(sync);
        }

        return (compilation, applied.Success ? null : applied.Error);
    }

    private void UpdateEnforcement(NftCompilation compilation, string? error, IReadOnlyList<CgroupPlacement> failures)
    {
        var now = _time.GetUtcNow();
        var rejected = compilation.Rejected.ToList();
        foreach (var failure in failures)
        {
            foreach (var rule in compilation.Applied.Where(rule => rule.CgroupPath == failure.TargetCgroup))
            {
                if (rejected.All(existing => existing.RuleId != rule.RuleId))
                {
                    rejected.Add(new NftRejectedRule(rule.RuleId, string.Create(CultureInfo.InvariantCulture, $"live process pid {failure.Pid} ({failure.ExePath}) could not be moved into {failure.TargetCgroup}: {failure.Error}")));
                }
            }
        }

        var appliedCount = compilation.Applied.Count(rule => rejected.All(existing => existing.RuleId != rule.RuleId));
        var previous = Enforcement;
        var report = new FilterEnforcementReport
        {
            // Readback fields are refreshed by RefreshAsync/ReadbackAsync; a batch result alone is "published".
            State = error is null ? FilterEnforcementState.Pending : FilterEnforcementState.Degraded,
            Connected = previous?.Connected ?? false,
            PublishedGeneration = _published,
            AckedGeneration = previous?.AckedGeneration,
            LastSeenUtc = _lastSeenUtc,
            LastAckUtc = _lastAckUtc,
            Generation = error is null ? compilation.Generation : (Enforcement?.Generation ?? -1),
            AppliedRuleCount = error is null ? appliedCount : (Enforcement?.AppliedRuleCount ?? 0),
            RejectedRules = rejected.Select(rule => new FilterRuleRejection { RuleId = rule.RuleId.ToString("D", CultureInfo.InvariantCulture), Reason = rule.Reason }).ToArray(),
            FileError = error,
            DroppedEvents = 0,
            ReportedUtc = now,
        };
        lock (_reportGate)
        {
            _enforcement = report;
        }

        if (error is null)
        {
            _events.Emit(FilterEventFormatter.Hello(report.Generation, 0, now));
        }

        _events.Emit(FilterEventFormatter.Rules(report.Generation, report.AppliedRuleCount, rejected, error, 0, now));
    }

    private static bool SameSpec(RuleSpec a, RuleSpec b) =>
        string.Equals(a.AppPath.Trim(), b.AppPath.Trim(), StringComparison.Ordinal) &&
        a.Direction == b.Direction &&
        a.Action == b.Action &&
        a.Protocol == b.Protocol &&
        (a.RemoteAddresses ?? []).Select(x => x.Trim()).SequenceEqual((b.RemoteAddresses ?? []).Select(x => x.Trim()), StringComparer.OrdinalIgnoreCase) &&
        string.Equals(a.RemotePorts?.Trim() ?? string.Empty, b.RemotePorts?.Trim() ?? string.Empty, StringComparison.Ordinal) &&
        a.Enabled == b.Enabled;

    private ManagedRuleState LoadState()
    {
        try
        {
            if (!File.Exists(_paths.ManagedRulesFile))
            {
                return new ManagedRuleState();
            }

            var state = JsonSerializer.Deserialize<ManagedRuleState>(File.ReadAllText(_paths.ManagedRulesFile), StateJson);
            return state is { SchemaVersion: ManagedRuleState.CurrentSchemaVersion }
                ? state with
                {
                    Rules = (state.Rules ?? [])
                        .Where(rule => rule.ManagedRuleId != Guid.Empty)
                        .Select(rule => string.IsNullOrWhiteSpace(rule.OwnershipGroup)
                            ? rule with { OwnershipGroup = OwnedRuleOwnership.GroupName }
                            : rule)
                        .ToList(),
                }
                : new ManagedRuleState();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new ManagedRuleState();
        }
    }

    private void SaveState(ManagedRuleState state) =>
        AtomicFile.Write(_paths.ManagedRulesFile, JsonSerializer.Serialize(state, StateJson) + "\n", AtomicFile.PrivateMode);

    private bool TryProbeWritable(out string problem)
    {
        try
        {
            Directory.CreateDirectory(_paths.FilterDirectory);
            var probe = Path.Combine(_paths.FilterDirectory, $".probe-{Guid.NewGuid():N}");
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            problem = string.Empty;
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            problem = exception.Message;
            return false;
        }
    }

    private void EnsureWriteGate()
    {
        if (!_writeGate())
        {
            throw new NotSupportedException(
                ProtectionWriteConsent.Granted
                    ? "Firewall writes require the root axiomd systemd service."
                    : "Firewall writes are disabled. Enable Axiom Shield in the app, or set " +
                      $"{FirewallWriteGate.WriteEnableVariable}=1 and {FirewallWriteGate.WriteConfirmVariable}=yes on an isolated test VM.");
        }
    }

    private static RuleApplyResult Failed(Guid id, string code, string message) => new()
    {
        Success = false,
        ManagedRuleId = id,
        State = RuleState.Failed,
        ErrorCode = code,
        ErrorMessage = message,
    };

    private sealed record ManagedRuleState
    {
        public const int CurrentSchemaVersion = 1;

        public int SchemaVersion { get; init; } = CurrentSchemaVersion;

        public long Generation { get; init; }

        public IReadOnlyList<ManagedRule> Rules { get; init; } = [];

        /// <summary>
        /// Removed rules whose connect-time (BPF) cleanup is not confirmed yet. Persisted so a daemon
        /// restart cannot forget them (restart-while-pending false clear); cleared only by a layer sync
        /// that wrote and read back maps without them.
        /// </summary>
        public IReadOnlyList<PendingRemoval> PendingRemovals { get; init; } = [];
    }
}

/// <summary>A removed rule whose BPF verdict cleanup is not confirmed (persisted in managed-rules.json).</summary>
public sealed record PendingRemoval(Guid RuleId, string AppPath, long Generation, string Reason, DateTimeOffset SinceUtc);

/// <summary>Write-temp-then-rename with a fixed mode (0600 private, 0644 published), as the macOS daemon does.</summary>
public static class AtomicFile
{
    public const UnixFileMode PrivateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    public const UnixFileMode PublishedMode = PrivateMode | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    public static void Write(string path, string content, UnixFileMode mode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(content);
        var directory = Path.GetDirectoryName(path) ?? ".";
        Directory.CreateDirectory(directory);
        var temp = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temp, content);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temp, mode);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }
}
