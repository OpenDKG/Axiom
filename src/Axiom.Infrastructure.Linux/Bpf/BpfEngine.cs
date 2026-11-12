// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Nft;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>
/// The connect-time verdict layer (docs/LINUX_EBPF.md): loads <c>axiom_connect.bpf.o</c> with
/// <c>bpftool prog loadall</c>, pins programs and maps under <c>/sys/fs/bpf/axiom</c>, attaches
/// the four programs at the cgroup root with <c>multi</c> (systemd's and Docker's cgroup programs
/// keep running), and after every nft publish rewrites the verdict maps from the same rule set
/// and generation (<see cref="BpfVerdictPlanner"/>). Everything goes through <c>bpftool</c> — no
/// libbpf binding in .NET — so a failure is a process result with stderr, never a crash. A probe
/// that says no leaves the daemon nft-only with the reason in <see cref="Status"/>.
/// <para>
/// Effective state (PR #276 review, LNX-1): <see cref="SyncAsync"/> writes the plan, reads the maps
/// back (<c>bpftool -j map dump</c>), repairs differences, retries a bounded number of times with
/// backoff, and returns a <see cref="LayerSyncResult"/>. When a stale entry still cannot be
/// deleted it detaches Axiom's own programs (never anyone else's) so the stale verdict cannot block,
/// and reports <see cref="Neutralised"/>; the supervisor re-attaches on its watch tick.
/// </para>
/// </summary>
public sealed class BpfEngine : IEnforcementLayer, IDisposable
{
    public static readonly TimeSpan DefaultEventsRestartDelay = TimeSpan.FromSeconds(2);

    /// <summary>Write passes per sync before neutralising (1 initial + 2 retries).</summary>
    public const int DefaultReconcileAttempts = 3;

    public static readonly TimeSpan DefaultReconcileBackoff = TimeSpan.FromMilliseconds(250);

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly IProcessRunner _runner;
    private readonly BpfEnginePaths _paths;
    private readonly IInodeReader _inodes;
    private readonly IAppCgroupResolver _cgroups;
    private readonly Func<IBpfEventSource>? _events;
    private readonly Func<int, string?> _exeOfPid;
    private readonly Func<Guid, (int Pid, string? Path)?> _fallback;
    private readonly IFilterEventSink _sink;
    private readonly bool _privileged;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, BpfMapEntry> _applied = new(StringComparer.Ordinal);
    private readonly object _stateGate = new();
    private string _status = "not started";
    private bool _active;
    private bool _neutralised;
    private long _generation = -1;
    private IReadOnlyList<BpfUncoveredRule> _uncovered = [];
    private LayerSyncResult? _lastSync;

    public BpfEngine(
        IProcessRunner runner,
        BpfEnginePaths paths,
        IInodeReader inodes,
        IAppCgroupResolver cgroups,
        Func<IBpfEventSource>? events,
        Func<int, string?> exeOfPid,
        Func<Guid, (int Pid, string? Path)?> fallback,
        IFilterEventSink sink,
        bool privileged,
        TimeProvider time)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _inodes = inodes ?? throw new ArgumentNullException(nameof(inodes));
        _cgroups = cgroups ?? throw new ArgumentNullException(nameof(cgroups));
        _events = events;
        _exeOfPid = exeOfPid ?? throw new ArgumentNullException(nameof(exeOfPid));
        _fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _privileged = privileged;
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <summary>Journal sink; set by the hosted service.</summary>
    public Action<string> Log { get; set; } = _ => { };

    public void Dispose() => _gate.Dispose();

    public TimeSpan EventsRestartDelay { get; init; } = DefaultEventsRestartDelay;

    /// <summary>Write passes per sync (bounded reconciliation).</summary>
    public int ReconcileAttempts { get; init; } = DefaultReconcileAttempts;

    /// <summary>Delay before the second pass; doubles per pass.</summary>
    public TimeSpan ReconcileBackoff { get; init; } = DefaultReconcileBackoff;

    public bool Active
    {
        get
        {
            lock (_stateGate)
            {
                return _active;
            }
        }
    }

    public string Status
    {
        get
        {
            lock (_stateGate)
            {
                return _status;
            }
        }
    }

    /// <inheritdoc />
    public bool Neutralised
    {
        get
        {
            lock (_stateGate)
            {
                return _neutralised;
            }
        }
    }

    /// <summary>Generation of the last fully applied map sync, -1 before the first (and after a failed one that was neutralised).</summary>
    public long Generation
    {
        get
        {
            lock (_stateGate)
            {
                return _generation;
            }
        }
    }

    /// <summary>Rules the last sync left to nftables alone.</summary>
    public IReadOnlyList<BpfUncoveredRule> Uncovered
    {
        get
        {
            lock (_stateGate)
            {
                return _uncovered;
            }
        }
    }

    /// <summary>Outcome of the last sync (null before the first).</summary>
    public LayerSyncResult? LastSync
    {
        get
        {
            lock (_stateGate)
            {
                return _lastSync;
            }
        }
    }

    /// <summary>Lines for the connection snapshot's limitations list.</summary>
    public IReadOnlyList<string> Limitations =>
        Active
            ? []
            : [$"The connect-time BPF layer is inactive ({Status}); a process that connects within ~1 s of exec is not blocked until the attribution poll herds it."];

    /// <summary>Applied map keys (hex) by map, for tests and <c>--doctor</c>.</summary>
    public IReadOnlyDictionary<string, BpfMapEntry> AppliedEntries
    {
        get
        {
            lock (_stateGate)
            {
                return new Dictionary<string, BpfMapEntry>(_applied, StringComparer.Ordinal);
            }
        }
    }

    public async Task StartAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var probe = BpfCapabilityProbe.Probe(_runner, _paths, _privileged);
            if (!probe.Usable)
            {
                SetState(false, "inactive: " + probe.Reason);
                Log($"BPF layer inactive: {probe.Reason}. nftables only; the exec-time race window stays open.");
                return;
            }

            // Startup reconciliation (LNX-2): a previous daemon that crashed leaves its programs attached
            // (pinned or not) with maps the new daemon cannot trust. Detach by pin and by name, unpin,
            // then load fresh so the maps start empty and are rebuilt from managed-rules.json.
            var orphans = DetachAndUnpin();
            if (orphans.Count > 0)
            {
                Log($"BPF layer: reconciled orphaned state from a previous daemon: {string.Join(", ", orphans)}.");
            }

            var load = Run("prog", "loadall", _paths.ObjectFile, _paths.PinDirectory, "pinmaps", _paths.MapDirectory);
            if (!load.Succeeded)
            {
                DetachAndUnpin();
                var reason = "inactive: bpftool prog loadall failed: " + Trim(load.StandardError);
                SetState(false, reason);
                Log("BPF layer " + reason);
                return;
            }

            foreach (var (hook, program) in BpfLayout.Programs)
            {
                var attach = Run("cgroup", "attach", _paths.CgroupRoot, hook, "pinned", _paths.ProgramPin(program), "multi");
                if (!attach.Succeeded)
                {
                    DetachAndUnpin();
                    var reason = $"inactive: attaching {program} at {_paths.CgroupRoot} ({hook}) failed: {Trim(attach.StandardError)}";
                    SetState(false, reason);
                    Log("BPF layer " + reason);
                    return;
                }
            }

            lock (_stateGate)
            {
                _applied.Clear();
                _generation = -1;
                _neutralised = false;
            }

            SetState(true, $"active ({probe.BpftoolVersion}; programs pinned at {_paths.PinDirectory})");
            Log($"BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at {_paths.CgroupRoot} (multi), pinned at {_paths.PinDirectory}.");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<LayerSyncResult> SyncAsync(IReadOnlyList<ManagedRule> rules, long generation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rules);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!Active)
            {
                var inactive = LayerSyncResult.Inactive(generation, Status, Directory.Exists(_paths.PinDirectory), Neutralised);
                lock (_stateGate)
                {
                    _lastSync = inactive;
                }

                return inactive;
            }

            var plan = BpfVerdictPlanner.Plan(rules.Select(rule => rule.Spec), generation, _cgroups, _inodes);
            var desired = plan.Entries.ToDictionary(entry => entry.Map + ":" + entry.KeyHex, StringComparer.Ordinal);
            Dictionary<string, BpfMapEntry> applied;
            lock (_stateGate)
            {
                applied = new Dictionary<string, BpfMapEntry>(_applied, StringComparer.Ordinal);
            }

            var failedDeletes = new List<LayerSyncFailure>();
            var failedUpdates = new List<LayerSyncFailure>();
            var verified = false;
            var attempts = 0;
            for (var attempt = 1; attempt <= Math.Max(1, ReconcileAttempts); attempt++)
            {
                attempts = attempt;
                failedDeletes.Clear();
                failedUpdates.Clear();
                WritePlan(desired, applied, failedDeletes, failedUpdates);
                verified = ReadBackAndRepair(desired, applied, failedDeletes, failedUpdates);
                if (failedDeletes.Count == 0 && failedUpdates.Count == 0)
                {
                    break;
                }

                if (attempt < ReconcileAttempts)
                {
                    var delay = TimeSpan.FromTicks(ReconcileBackoff.Ticks * (1L << (attempt - 1)));
                    Log(string.Create(CultureInfo.InvariantCulture, $"BPF verdicts generation {generation}: pass {attempt} left {failedDeletes.Count} stale and {failedUpdates.Count} missing entries; retrying in {delay.TotalMilliseconds:0} ms."));
                    await Task.Delay(delay, _time, ct).ConfigureAwait(false);
                }
            }

            var neutralised = false;
            if (failedDeletes.Count > 0)
            {
                // A verdict the rule set no longer wants is still in an attached map and would keep
                // blocking: the only safe move left is to stop enforcing anything from this layer.
                Log(string.Create(CultureInfo.InvariantCulture, $"BPF verdicts generation {generation}: {failedDeletes.Count} stale entr{(failedDeletes.Count == 1 ? "y" : "ies")} could not be deleted after {attempts} passes ({string.Join("; ", failedDeletes)}); neutralising: detaching Axiom's programs at {_paths.CgroupRoot} (third-party programs untouched)."));
                DetachAndUnpin();
                var remaining = ListAttachedAxiomPrograms();
                if (remaining.Count > 0)
                {
                    // Detach failed too: the stale verdict still enforces. Say so; never pretend otherwise.
                    Log($"BPF layer: {remaining.Count} program(s) still attached after the detach ({string.Join(", ", remaining.Select(program => program.Name))}); the stale entries can still block.");
                }
                else
                {
                    neutralised = true;
                    applied.Clear();
                }
            }

            var detachedExternally = false;
            if (!neutralised && ProgramsAttached() is { } attachedCount && attachedCount < BpfLayout.Programs.Count)
            {
                // Someone detached Axiom's programs (bpftool cgroup detach, a cgroup tool): the maps no
                // longer enforce anything. Report it and let the watcher re-attach (Neutralised).
                detachedExternally = true;
                Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: only {attachedCount} of {BpfLayout.Programs.Count} Axiom programs are attached at {_paths.CgroupRoot}; connect-time verdicts are not enforced until re-attached."));
            }

            var attached = !neutralised && !detachedExternally;
            if (failedDeletes.Count > 0 && !neutralised)
            {
                lock (_stateGate)
                {
                    _status = string.Create(CultureInfo.InvariantCulture, $"degraded: {failedDeletes.Count} stale map entr{(failedDeletes.Count == 1 ? "y" : "ies")} could not be deleted and the programs could not be detached (generation {generation})");
                }
            }
            lock (_stateGate)
            {
                _applied.Clear();
                foreach (var (id, entry) in applied)
                {
                    _applied[id] = entry;
                }

                _generation = failedDeletes.Count == 0 && failedUpdates.Count == 0 ? generation : neutralised ? -1 : _generation;
                _uncovered = plan.Uncovered;
                if (detachedExternally)
                {
                    _active = false;
                    _neutralised = true;
                    _status = string.Create(CultureInfo.InvariantCulture, $"degraded: Axiom's BPF programs were detached by another tool (generation {generation}); nftables only until re-attached");
                }

                if (neutralised)
                {
                    _active = false;
                    _neutralised = true;
                    _status = string.Create(CultureInfo.InvariantCulture, $"degraded: detached after {failedDeletes.Count} stale map entr{(failedDeletes.Count == 1 ? "y" : "ies")} could not be deleted (generation {generation}); nftables only until re-attached");
                }
            }

            var result = new LayerSyncResult
            {
                Generation = generation,
                Attached = attached,
                Pinned = Directory.Exists(_paths.PinDirectory),
                Applied = attached && failedDeletes.Count == 0 && failedUpdates.Count == 0,
                Verified = attached && verified && failedDeletes.Count == 0 && failedUpdates.Count == 0,
                Neutralised = neutralised || detachedExternally,
                Attempts = attempts,
                FailedDeletes = failedDeletes.ToList(),
                FailedUpdates = failedUpdates.ToList(),
                // A rule whose exe key could not be proven (or that is a directory) may still have a cgroup
                // entry; it is reported uncovered, never "BPF-backed" (the exec window is not closed for it).
                CoveredRules = attached ? plan.Entries.Select(entry => BpfLayout.ParseRuleId(Convert.ToHexStringLower(entry.Value.AsSpan(8, 16)))).OfType<Guid>().Distinct().Where(id => plan.Uncovered.All(rule => rule.RuleId != id)).ToList() : [],
                Uncovered = plan.Uncovered.Select(rule => new LayerUncoveredRule(rule.RuleId, rule.Reason)).ToList(),
                Status = Status,
            };
            lock (_stateGate)
            {
                _lastSync = result;
            }

            var failures = failedDeletes.Concat(failedUpdates).ToList();
            Log(string.Create(
                CultureInfo.InvariantCulture,
                $"BPF verdicts generation {generation}: {plan.ExeEntries} exe, {plan.CgroupEntries} cgroup entries; {plan.Uncovered.Count} rule(s) left to nftables{(failures.Count == 0 ? (verified ? " (read back verified)." : " (written; read-back unavailable).") : "; " + failures.Count + " map write(s) failed after " + attempts + " pass(es): " + string.Join("; ", failures) + (neutralised ? "; layer neutralised" : string.Empty))}"));
            foreach (var entry in plan.Entries.Where(entry => entry.Map == BpfLayout.ExeMap))
            {
                Log($"BPF exe key: {entry.Describe}.");
            }

            foreach (var rule in plan.Uncovered.Where(rule => rule.Reason.StartsWith("exe key not provable", StringComparison.Ordinal)))
            {
                Log($"BPF exe key: rule {rule.RuleId} left to nftables: {rule.Reason}.");
            }

            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!Active && !Directory.Exists(_paths.PinDirectory))
            {
                // Still detach by name: a crashed daemon's programs may be attached without pins.
                DetachAndUnpin();
                SetState(false, "stopped");
                return;
            }

            DetachAndUnpin();
            lock (_stateGate)
            {
                _applied.Clear();
                _generation = -1;
                _neutralised = false;
            }

            SetState(false, "stopped");
            Log($"BPF layer detached and {_paths.PinDirectory} removed.");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RunEventsAsync(CancellationToken ct)
    {
        if (_events is null)
        {
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            if (!Active)
            {
                await Task.Delay(EventsRestartDelay, _time, ct).ConfigureAwait(false);
                continue;
            }

            try
            {
                var monitor = new BpfEventMonitor(_events(), _exeOfPid, _fallback, _sink, _time);
                await monitor.RunAsync(ct).ConfigureAwait(false);
                Log("axiom-bpf-events exited; restarting.");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                Log($"axiom-bpf-events failed: {exception.Message}; restarting.");
            }

            await Task.Delay(EventsRestartDelay, _time, ct).ConfigureAwait(false);
        }
    }

    /// <summary>One write pass: delete what the plan no longer wants, update what it wants.</summary>
    private void WritePlan(Dictionary<string, BpfMapEntry> desired, Dictionary<string, BpfMapEntry> applied, List<LayerSyncFailure> failedDeletes, List<LayerSyncFailure> failedUpdates)
    {
        foreach (var (id, stale) in applied.Where(pair => !desired.ContainsKey(pair.Key)).ToList())
        {
            if (TryDelete(stale, out var error))
            {
                applied.Remove(id);
            }
            else
            {
                failedDeletes.Add(Failure("delete", stale, error));
            }
        }

        foreach (var (id, entry) in desired)
        {
            if (TryUpdate(entry, out var error))
            {
                applied[id] = entry;
            }
            else
            {
                failedUpdates.Add(Failure("update", entry, error));
            }
        }
    }

    /// <summary>
    /// Reads both verdict maps back and repairs them against the plan: unknown keys (a crashed
    /// daemon's leftovers, a delete that lied) are deleted, missing or different entries rewritten.
    /// Returns true when the read-back worked and, after repairs, matched the plan exactly.
    /// </summary>
    private bool ReadBackAndRepair(Dictionary<string, BpfMapEntry> desired, Dictionary<string, BpfMapEntry> applied, List<LayerSyncFailure> failedDeletes, List<LayerSyncFailure> failedUpdates)
    {
        var consistent = true;
        foreach (var map in new[] { BpfLayout.ExeMap, BpfLayout.CgroupMap })
        {
            var dump = Run("-j", "map", "dump", "pinned", _paths.MapPin(map));
            if (!dump.Succeeded)
            {
                Log($"BPF layer: read-back of {map} failed: {Trim(dump.StandardError)}");
                return false;
            }

            var live = BpfMapDump.Parse(dump.StandardOutput);
            if (live is null)
            {
                Log($"BPF layer: read-back of {map} returned unexpected output.");
                return false;
            }

            var wanted = desired.Values.Where(entry => entry.Map == map).ToDictionary(entry => entry.KeyHex, StringComparer.Ordinal);
            foreach (var (keyHex, valueHex) in live)
            {
                if (wanted.TryGetValue(keyHex, out var entry))
                {
                    if (!string.Equals(valueHex, BpfLayout.HexString(entry.Value), StringComparison.Ordinal))
                    {
                        consistent = false;
                        if (!TryUpdate(entry, out var error))
                        {
                            failedUpdates.RemoveAll(failure => failure.Map == map && failure.KeyHex == keyHex);
                            failedUpdates.Add(Failure("update", entry, error));
                        }
                    }

                    continue;
                }

                consistent = false;
                var stale = new BpfMapEntry(map, Convert.FromHexString(keyHex), Convert.FromHexString(valueHex), $"unknown {map} key {keyHex}");
                if (TryDelete(stale, out var deleteError))
                {
                    applied.Remove(map + ":" + keyHex);
                    failedDeletes.RemoveAll(failure => failure.Map == map && failure.KeyHex == keyHex);
                }
                else if (failedDeletes.All(failure => !(failure.Map == map && failure.KeyHex == keyHex)))
                {
                    failedDeletes.Add(Failure("delete", applied.TryGetValue(map + ":" + keyHex, out var known) ? known : stale, deleteError));
                }
            }

            foreach (var (keyHex, entry) in wanted)
            {
                if (live.ContainsKey(keyHex))
                {
                    continue;
                }

                consistent = false;
                if (TryUpdate(entry, out var error))
                {
                    applied[map + ":" + keyHex] = entry;
                    failedUpdates.RemoveAll(failure => failure.Map == map && failure.KeyHex == keyHex);
                }
                else if (failedUpdates.All(failure => !(failure.Map == map && failure.KeyHex == keyHex)))
                {
                    failedUpdates.Add(Failure("update", entry, error));
                }
            }
        }

        // Successful deletes/updates during the repair are not reflected in failed* unless they failed;
        // "verified" means the read-back happened and nothing needed repairing or every repair succeeded.
        return consistent || (failedDeletes.Count == 0 && failedUpdates.Count == 0);
    }

    private bool TryDelete(BpfMapEntry entry, out string error)
    {
        if (!File.Exists(_paths.MapPin(entry.Map)))
        {
            // ENOENT from a missing pin is not "key already gone": the map may still be attached, unpinned.
            error = $"map pin {_paths.MapPin(entry.Map)} is missing; the entry cannot be deleted or confirmed absent";
            return false;
        }

        var delete = Run(["map", "delete", "pinned", _paths.MapPin(entry.Map), "key", "hex", .. BpfLayout.HexTokens(entry.Key)]);
        if (delete.Succeeded || (delete.StandardError.Contains("No such", StringComparison.OrdinalIgnoreCase) && !delete.StandardError.Contains("obj get", StringComparison.OrdinalIgnoreCase)))
        {
            error = string.Empty;
            return true;
        }

        error = Trim(delete.StandardError);
        return false;
    }

    private bool TryUpdate(BpfMapEntry entry, out string error)
    {
        var update = Run(["map", "update", "pinned", _paths.MapPin(entry.Map), "key", "hex", .. BpfLayout.HexTokens(entry.Key), "value", "hex", .. BpfLayout.HexTokens(entry.Value), "any"]);
        error = update.Succeeded ? string.Empty : Trim(update.StandardError);
        return update.Succeeded;
    }

    private static LayerSyncFailure Failure(string operation, BpfMapEntry entry, string error) =>
        new(operation, entry.Map, entry.KeyHex, entry.Value.Length >= 24 ? BpfLayout.ParseRuleId(Convert.ToHexStringLower(entry.Value.AsSpan(8, 16))) : null, entry.Describe, error);

    /// <summary>
    /// Detaches every Axiom program (by pin when pinned, else by name from <c>bpftool cgroup show</c>)
    /// and unlinks the pin tree. Only programs named <c>axiom_*</c> are touched. Returns what it found.
    /// </summary>
    private List<string> DetachAndUnpin()
    {
        var found = new List<string>();
        foreach (var (hook, program) in BpfLayout.Programs)
        {
            var pin = _paths.ProgramPin(program);
            if (File.Exists(pin))
            {
                Run("cgroup", "detach", _paths.CgroupRoot, hook, "pinned", pin);
                found.Add($"pinned {program}");
            }
        }

        foreach (var (hook, id, name) in ListAttachedAxiomPrograms())
        {
            var detach = Run("cgroup", "detach", _paths.CgroupRoot, hook, "id", id.ToString(CultureInfo.InvariantCulture));
            if (detach.Succeeded)
            {
                found.Add($"attached {name} id {id}");
            }
        }

        try
        {
            if (Directory.Exists(_paths.PinDirectory))
            {
                Directory.Delete(_paths.PinDirectory, recursive: true);
                found.Add("pins " + _paths.PinDirectory);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Log($"BPF layer: could not remove {_paths.PinDirectory}: {exception.Message}");
        }

        return found;
    }

    /// <summary>Number of Axiom programs attached at the cgroup root, or null when <c>bpftool cgroup show</c> is unreadable.</summary>
    private int? ProgramsAttached()
    {
        var show = Run("-j", "cgroup", "show", _paths.CgroupRoot);
        if (!show.Succeeded)
        {
            return null;
        }

        var names = BpfLayout.Programs.Select(program => program.Program).ToHashSet(StringComparer.Ordinal);
        return BpfMapDump.ParseAttached(show.StandardOutput).Select(program => program.Name).Where(names.Contains).Distinct(StringComparer.Ordinal).Count();
    }

    /// <summary>Axiom's programs still attached at the cgroup root (name prefix <c>axiom_</c> as in <see cref="BpfLayout.Programs"/>).</summary>
    private List<(string Hook, long Id, string Name)> ListAttachedAxiomPrograms()
    {
        var show = Run("-j", "cgroup", "show", _paths.CgroupRoot);
        if (!show.Succeeded)
        {
            return [];
        }

        var hooks = BpfLayout.Programs.ToDictionary(program => program.Program, program => program.Hook, StringComparer.Ordinal);
        return BpfMapDump.ParseAttached(show.StandardOutput)
            .Where(attached => hooks.ContainsKey(attached.Name))
            .Select(attached => (hooks[attached.Name], attached.Id, attached.Name))
            .ToList();
    }

    private ProcessResult Run(params string[] arguments) => Run((IReadOnlyList<string>)arguments);

    /// <summary>One bpftool call; a missing/unrunnable bpftool is a failed result (exit 127), never an exception.</summary>
    private ProcessResult Run(IReadOnlyList<string> arguments)
    {
        try
        {
            return _runner.Run(BpfCapabilityProbe.Bpftool, arguments, Timeout);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new ProcessResult(127, string.Empty, $"bpftool could not be run: {exception.Message}");
        }
    }

    private void SetState(bool active, string status)
    {
        lock (_stateGate)
        {
            _active = active;
            _status = status;
        }
    }

    private static string Trim(string text)
    {
        var line = text.Trim();
        return line.Length > 300 ? line[..300] + "…" : line.Length == 0 ? "(no output)" : line;
    }
}

/// <summary>Parsers for the bpftool JSON read-backs the engine relies on (pure; unit-tested).</summary>
public static class BpfMapDump
{
    /// <summary>
    /// <c>bpftool -j map dump pinned …</c>: an array of <c>{"key":["0x08",…],"value":["0x02",…],"formatted":{…}}</c>
    /// (the raw byte arrays are always present; <c>formatted</c> only with BTF). Returns key hex → value hex,
    /// or null when the output is not that shape.
    /// </summary>
    public static Dictionary<string, string>? Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var entries = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (!element.TryGetProperty("key", out var key) || !element.TryGetProperty("value", out var value))
                {
                    continue;
                }

                var keyHex = Bytes(key);
                var valueHex = Bytes(value);
                if (keyHex is null || valueHex is null)
                {
                    return null;
                }

                entries[keyHex] = valueHex;
            }

            return entries;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary><c>bpftool -j cgroup show &lt;root&gt;</c>: <c>[{"id":N,"attach_type":"…","attach_flags":"multi","name":"…"}]</c>.</summary>
    public static IReadOnlyList<(long Id, string Name, string AttachType)> ParseAttached(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return [];
            }

            var programs = new List<(long, string, string)>();
            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.Number)
                {
                    continue;
                }

                var name = element.TryGetProperty("name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String ? nameElement.GetString() ?? string.Empty : string.Empty;
                var type = element.TryGetProperty("attach_type", out var typeElement) && typeElement.ValueKind == JsonValueKind.String ? typeElement.GetString() ?? string.Empty : string.Empty;
                programs.Add((id.GetInt64(), name, type));
            }

            return programs;
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string? Bytes(JsonElement array)
    {
        if (array.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var bytes = new List<byte>();
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { } text)
            {
                var hex = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text[2..] : text;
                if (!byte.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
                {
                    return null;
                }

                bytes.Add(value);
            }
            else if (item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out var number) && number is >= 0 and <= 255)
            {
                bytes.Add((byte)number);
            }
            else
            {
                return null;
            }
        }

        return Convert.ToHexStringLower(bytes.ToArray());
    }
}
