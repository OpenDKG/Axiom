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
            FilterEnforcementState.Degraded =>
                "table inet axiom is missing (another tool may have flushed the ruleset); rules are stored but not enforced until republished.",
            FilterEnforcementState.Pending => string.Create(
                CultureInfo.InvariantCulture,
                $"nftables holds generation {enforcement.AckedGeneration?.ToString(CultureInfo.InvariantCulture) ?? "none"}; generation {enforcement.PublishedGeneration} is pending."),
            _ => null,
        };

        return new FirewallCapabilityReport
        {
            // Pending (table holds another generation for a moment) stays Available with a reason, as on macOS;
            // Degraded is the lost/foreign table, unreadable nft or a rejected batch.
            Status = enforcement.State == FilterEnforcementState.Degraded ? FirewallCapabilityStatus.Degraded : FirewallCapabilityStatus.Available,
            Reason = reason,
            FirewallServiceRunning = enforcement.Connected,
            ManagedRulesReadable = true,
            ManagedRuleCount = state.Rules.Count,
            ProbedUtc = now,
            FilterEnforcement = enforcement,
            Limitations = Limitations(),
        };
    }

    /// <summary>
    /// Whether a connect-time verdict layer (docs/LINUX_EBPF.md) is attached right now; false =
    /// nftables is the only boundary and the exec race is open.
    /// </summary>
    public bool ConnectTimeLayerActive { get; set; }

    /// <summary>Limitations of this enforcement build (shown with the capability report).</summary>
    public IReadOnlyList<string> Limitations() =>
        ConnectTimeLayerActive ? [ExecRaceLimitation + " The BPF layer closes this window for unscoped outbound block rules."] : [ExecRaceLimitation, BpfLayerInactiveLimitation];

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

            return new Readback(generation, generation is null ? [] : NftTable.ParseCounters(json), null, now);
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

    private FilterEnforcementReport Rebuild(Readback readback)
    {
        lock (_reportGate)
        {
            var previous = _enforcement;
            var fileRejected = previous?.FileError is { Length: > 0 };
            var state = Evaluate(_published, readback.Generation, readback.NftError is null, fileRejected);
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
        return Task.FromResult<IReadOnlyList<ManagedRule>>(
            LoadState().Rules.Select(rule => rule with { State = ProjectState(rule, report, compilation) }).ToList());
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
            var result = Outcome(spec, rule.OsRuleName, outcome.Compilation, readback.Generation, readback.Counters, report, CgroupPresent(outcome.Compilation, spec.ManagedRuleId), _attributionFailures);
            SaveState(new ManagedRuleState
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
    /// </summary>
    public static RuleApplyResult Outcome(
        RuleSpec spec,
        string? osRuleName,
        NftCompilation compilation,
        long? liveGeneration,
        IReadOnlyList<NftRuleCounter> counters,
        FilterEnforcementReport report,
        bool cgroupExists,
        IReadOnlyList<CgroupPlacement> attributionFailures)
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

            // Gone from the batch; verified gone only when the readback shows the new generation without it.
            var readback = await ReadbackAsync(ct).ConfigureAwait(false);
            var report = Rebuild(readback);
            var verified = report.State == FilterEnforcementState.Verified && readback.Counters.All(counter => counter.RuleId != managedRuleId);
            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                OsRuleName = existing?.OsRuleName,
                VerifiedUtc = verified ? readback.At : null,
                ErrorMessage = verified ? null : string.Create(CultureInfo.InvariantCulture, $"removed from the batch; generation {outcome.Compilation.Generation} not verified in nftables yet"),
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
        if (!verified && stored is not null && rejection is null)
        {
            notes.Add($"Enforcement not verified: state {report.State.ToString().ToLowerInvariant()}.");
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

    /// <summary>Deletes the table, returns herded processes and removes the Axiom cgroups (daemon stop / uninstall).</summary>
    public async Task TeardownAsync(CancellationToken ct)
    {
        await _table.DeleteAsync(ct).ConfigureAwait(false);
        _cgroups.RemoveAll();
        _tableApplied = false;
        _published = -1;
        lock (_reportGate)
        {
            _enforcement = null;
        }
    }

    private async Task<(NftCompilation Compilation, string? Error)> PublishAsync(IReadOnlyList<ManagedRule> rules, long stateGeneration, CancellationToken ct)
    {
        var tableGeneration = await _table.ReadGenerationAsync(ct).ConfigureAwait(false) ?? 0;
        var generation = Math.Max(stateGeneration, tableGeneration) + 1;
        // Persist ownership first: a crash between the two steps leaves the next start able to
        // republish the complete table, never a table with rules the daemon no longer knows.
        SaveState(new ManagedRuleState { Generation = generation, Rules = rules });
        _cgroups.Retain(rules.Where(rule => rule.Spec.Enabled).Select(rule => rule.Spec.AppPath.Trim()));
        var compilation = NftRuleCompiler.Compile(rules.Select(rule => rule.Spec), generation, _cgroups);
        AtomicFile.Write(_paths.RulesFile, compilation.Script, AtomicFile.PublishedMode);
        var applied = await _table.ApplyAsync(compilation.Script, ct).ConfigureAwait(false);
        var placements = applied.Success ? _cgroups.Attribute().Placements.Where(placement => !placement.Moved).ToList() : [];
        _tableApplied = applied.Success;
        _lastCompilation = compilation;
        if (applied.Success)
        {
            _published = generation;
            _attributionFailures = placements;
        }

        UpdateEnforcement(compilation, applied.Success ? null : applied.Error, placements);
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
    }
}

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
