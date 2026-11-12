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
            };
        }

        var state = LoadState();
        var enforcement = Enforcement;
        var tableGeneration = await _table.ReadGenerationAsync(ct).ConfigureAwait(false);
        string? reason = null;
        var status = FirewallCapabilityStatus.Available;
        if (enforcement?.FileError is { Length: > 0 } error)
        {
            status = FirewallCapabilityStatus.Degraded;
            reason = $"nftables rejected the last Axiom table ({error}); the previous generation stays in force.";
        }
        else if (enforcement is not null && tableGeneration is null)
        {
            status = FirewallCapabilityStatus.Degraded;
            reason = "table inet axiom is missing (another tool may have flushed the ruleset); rules are stored but not enforced until republished.";
        }
        else if (enforcement is not null && tableGeneration < enforcement.Generation)
        {
            reason = string.Create(CultureInfo.InvariantCulture, $"nftables holds generation {tableGeneration}; generation {enforcement.Generation} is pending.");
        }

        return new FirewallCapabilityReport
        {
            Status = status,
            Reason = reason,
            FirewallServiceRunning = tableGeneration is not null,
            ManagedRulesReadable = true,
            ManagedRuleCount = state.Rules.Count,
            ProbedUtc = now,
            FilterEnforcement = enforcement,
        };
    }

    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<ManagedRule>>(LoadState().Rules);
    }

    public async Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        EnsureWriteGate();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _time.GetUtcNow();
            var state = LoadState();
            var rule = new ManagedRule
            {
                ManagedRuleId = spec.ManagedRuleId,
                OsRuleName = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction),
                OwnershipGroup = OwnedRuleOwnership.GroupName,
                Spec = spec,
                State = RuleState.Applied,
                LastVerifiedUtc = now,
            };
            var rules = state.Rules.Where(existing => existing.ManagedRuleId != spec.ManagedRuleId).Append(rule).ToList();
            var outcome = await PublishAsync(rules, state.Generation, ct).ConfigureAwait(false);
            if (outcome.Error is { } error)
            {
                return Failed(spec.ManagedRuleId, "nft.apply_failed", error) with { OsRuleName = rule.OsRuleName };
            }

            // The report also carries live-process placement failures found right after the apply.
            var id = spec.ManagedRuleId.ToString("D", CultureInfo.InvariantCulture);
            var rejection = Enforcement?.RejectedRules.FirstOrDefault(rejected => string.Equals(rejected.RuleId, id, StringComparison.OrdinalIgnoreCase));
            if (rejection is not null && spec.Enabled)
            {
                // Stored and reported (the UI shows it under "not enforced"), like a macOS filter rejection.
                return new RuleApplyResult
                {
                    Success = true,
                    ManagedRuleId = spec.ManagedRuleId,
                    State = RuleState.Pending,
                    OsRuleName = rule.OsRuleName,
                    ErrorCode = "nft.rule_rejected",
                    ErrorMessage = rejection.Reason,
                    VerifiedUtc = now,
                };
            }

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = spec.ManagedRuleId,
                State = RuleState.Applied,
                OsRuleName = rule.OsRuleName,
                VerifiedUtc = now,
            };
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

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                OsRuleName = existing?.OsRuleName,
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
        var tableGeneration = await _table.ReadGenerationAsync(ct).ConfigureAwait(false);
        var counters = tableGeneration is null
            ? []
            : (await _table.ReadCountersAsync(ct).ConfigureAwait(false)).Where(counter => counter.RuleId == spec.ManagedRuleId).ToList();
        var notes = new List<string>
        {
            string.Create(CultureInfo.InvariantCulture, $"managed-rules.json generation {state.Generation}."),
        };
        if (tableGeneration is null)
        {
            notes.Add("table inet axiom is not present; the rule is stored but not enforced.");
        }
        else
        {
            notes.Add(string.Create(CultureInfo.InvariantCulture, $"table inet axiom generation {tableGeneration}, {counters.Count} nft rule(s), {counters.Sum(counter => counter.Packets)} packet(s) matched."));
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
        if (Enforcement is { } report)
        {
            if (report.FileError is { Length: > 0 } fileError)
            {
                notes.Add(string.Create(CultureInfo.InvariantCulture, $"nftables rejected the last batch ({fileError}); generation {report.Generation} stays in force."));
            }

            rejection = report.RejectedRules
                .FirstOrDefault(rejected => Guid.TryParse(rejected.RuleId, out var id) && id == spec.ManagedRuleId)
                ?.Reason;
            if (rejection is not null)
            {
                notes.Add($"The nftables engine rejected this rule and does not enforce it: {rejection}");
            }
        }

        var present = stored is not null && counters.Count > 0;
        return new EffectiveRuleReport
        {
            ManagedRuleId = spec.ManagedRuleId,
            PresentInOs = present,
            MatchesSpec = matches,
            EffectiveAction = present && stored is { Spec.Enabled: true } && rejection is null ? stored.Spec.Action : null,
            ObservedUtc = now,
            Notes = notes,
            FilterRejectionReason = rejection,
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
        var report = new FilterEnforcementReport
        {
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
