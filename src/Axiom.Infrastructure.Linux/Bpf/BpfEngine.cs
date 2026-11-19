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
    private string _status = "pending: not started yet; connect-time blocking is not verified";
    private bool _pending = true;
    private BpfEnginePaths _pins;
    private Handover? _handover;
    private List<(string Hook, long Id, string Name)> _retire = [];
    private bool _active;
    private bool _neutralised;
    private bool _staleProgramsAttached;
    private bool _attachmentUnknown;
    private string _activeStatus = "active";
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
        _pins = paths;
    }

    /// <summary>
    /// Where a new program set is staged while a previous daemon's set still enforces (docs/LINUX_EBPF.md §12).
    /// No '.' in the name: bpffs refuses it in any name it creates (kernel <c>bpf_lookup</c> returns -EPERM).
    /// </summary>
    public string StagingDirectory => _paths.PinDirectory + "-next";

    /// <summary>A new set attached next to a previous daemon's set, not yet populated (make-before-break).</summary>
    private sealed record Handover(IReadOnlyList<(string Hook, long Id, string Name)> Old, IReadOnlyList<long> NewIds);

    /// <summary>Journal sink; set by the hosted service.</summary>
    public Action<string> Log { get; set; } = _ => { };

    /// <summary>Path whose exe key the self-check compares (the daemon's own image via /proc/&lt;pid&gt;/exe).</summary>
    public string SelfExePath { get; init; } = "/proc/" + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + "/exe";

    /// <summary>Process id the program records the self-check for.</summary>
    public int SelfPid { get; init; } = Environment.ProcessId;

    /// <summary>Makes one connect() from this process so the program records its key (UDP to 127.0.0.1:9; no packet).</summary>
    public Action SelfCheckConnect { get; init; } = ConnectLoopbackUdp;

    /// <summary>Result of the kernel/user-space exe key self-check of the loaded program (docs/LINUX_EBPF.md §2.1).</summary>
    public BpfKernelKeyCheck KernelKeyCheck
    {
        get
        {
            lock (_stateGate)
            {
                return _kernelKey;
            }
        }
    }

    private BpfKernelKeyCheck _kernelKey = BpfKernelKeyCheck.Unverified("layer not attached");

    /// <summary>One UDP connect() to 127.0.0.1:9: runs the connect4 hook, sends no packet.</summary>
    private static void ConnectLoopbackUdp()
    {
        using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
        socket.Connect(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 9));
    }

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

    /// <inheritdoc />
    public bool CheckAttached()
    {
        if (!Active)
        {
            return false;
        }

        var attached = ProgramsAttached(out var unreadable);
        if (attached is null)
        {
            // PR #276 review, finding 4: unreadable is unknown, never "detached". Keep the pins and the
            // loaded set (no re-attach, which would load a second set) and say that nothing is confirmed.
            bool first;
            lock (_stateGate)
            {
                first = !_attachmentUnknown;
                _attachmentUnknown = true;
                _status = UnknownStatus(unreadable, "pins and the loaded program set are kept; no new set is loaded");
            }

            if (first)
            {
                Log($"BPF layer: cannot confirm whether Axiom's programs are attached at {_paths.CgroupRoot} ({unreadable}); keeping {_paths.PinDirectory} and the loaded set, loading no new set, and keeping removals pending until bpftool reads again.");
            }

            return false;
        }

        if (attached < BpfLayout.Programs.Count)
        {
            lock (_stateGate)
            {
                _attachmentUnknown = false;
                _active = false;
                _neutralised = true;
                _status = string.Create(CultureInfo.InvariantCulture, $"degraded: only {attached} of {BpfLayout.Programs.Count} Axiom BPF programs are attached (detached by another tool); nftables only until re-attached");
            }

            Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: only {attached} of {BpfLayout.Programs.Count} Axiom programs are attached at {_paths.CgroupRoot} (detached by another tool); connect-time verdicts are not enforced until re-attached."));
            return false;
        }

        bool recovered;
        lock (_stateGate)
        {
            recovered = _attachmentUnknown;
            if (recovered)
            {
                _attachmentUnknown = false;
                _status = _activeStatus;
            }
        }

        if (recovered)
        {
            Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: attachment state readable again: {attached} of {BpfLayout.Programs.Count} Axiom programs attached at {_paths.CgroupRoot}."));
        }

        return true;
    }

    private string UnknownStatus(string unreadable, string consequence) =>
        $"unknown: the daemon cannot confirm whether its BPF programs are attached at {_paths.CgroupRoot} ({unreadable}); {consequence}; connect-time verdicts may still be enforced";

    /// <inheritdoc />
    public IReadOnlyList<Guid> StaleExeKeys(IReadOnlyList<ManagedRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (!Active)
        {
            return [];
        }

        var plan = BpfVerdictPlanner.Plan(rules.Select(rule => rule.Spec), Generation, _cgroups, _inodes, KernelKeyCheck);
        HashSet<string> applied;
        lock (_stateGate)
        {
            applied = _applied.Values.Where(entry => entry.Map == BpfLayout.ExeMap).Select(entry => entry.KeyHex).ToHashSet(StringComparer.Ordinal);
        }

        var desired = plan.Entries.Where(entry => entry.Map == BpfLayout.ExeMap).ToList();
        var desiredKeys = desired.Select(entry => entry.KeyHex).ToHashSet(StringComparer.Ordinal);
        List<BpfMapEntry> stale;
        lock (_stateGate)
        {
            stale = desired.Where(entry => !applied.Contains(entry.KeyHex))
                .Concat(_applied.Values.Where(entry => entry.Map == BpfLayout.ExeMap && !desiredKeys.Contains(entry.KeyHex)))
                .ToList();
        }

        return stale.Select(entry => BpfLayout.ParseRuleId(Convert.ToHexStringLower(entry.Value.AsSpan(8, 16)))).OfType<Guid>().Distinct().ToList();
    }

    /// <inheritdoc />
    public bool Pending
    {
        get
        {
            lock (_stateGate)
            {
                return _pending;
            }
        }
    }

    /// <inheritdoc />
    public async Task HandOverAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            Handover? handover;
            lock (_stateGate)
            {
                handover = _handover;
            }

            if (handover is not null)
            {
                // Stopped before the new set took over: drop the unpopulated new set, the old one keeps enforcing.
                RollBackNewSet(handover, "the daemon stopped before the new set took over", markStale: false);
            }

            bool anything;
            lock (_stateGate)
            {
                anything = _active || _staleProgramsAttached || _attachmentUnknown || _neutralised || handover is not null;
                _active = false;
                _pending = false;
                _handover = null;
                _status = anything
                    ? $"handed over: Axiom's programs and pinned maps at {_pins.PinDirectory} are left attached for the next daemon, which replaces them make-before-break"
                    : "stopped";
            }

            if (anything)
            {
                Log($"BPF layer: programs and pinned maps at {_pins.PinDirectory} left attached for the next daemon (restart or upgrade): connect-time verdicts keep enforcing while the daemon is down; the next start replaces them make-before-break.");
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task AbortStartAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            Handover? handover;
            lock (_stateGate)
            {
                handover = _handover;
            }

            if (handover is not null)
            {
                RollBackNewSet(handover, "its maps could not be populated from managed-rules.json (no published table yet)", markStale: true);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public bool AttachmentUnknown
    {
        get
        {
            lock (_stateGate)
            {
                return _attachmentUnknown;
            }
        }
    }

    /// <inheritdoc />
    public bool StaleProgramsAttached
    {
        get
        {
            lock (_stateGate)
            {
                return _staleProgramsAttached;
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
            lock (_stateGate)
            {
                _pending = true;
            }

            BpfProbeResult probe;
            try
            {
                probe = BpfCapabilityProbe.Probe(_runner, _paths, _privileged);
            }
            catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException)
            {
                probe = new BpfProbeResult(false, "bpftool could not be run: " + exception.Message, null);
            }

            if (!probe.Usable && (Directory.Exists(_paths.PinDirectory) || Directory.Exists(StagingDirectory)))
            {
                // A previous daemon's set may still be attached (it is handed over on restart, §12) and
                // enforcing verdicts of rules removed since. Without a usable bpftool it can neither be
                // listed nor replaced: report it as unknown/stale (degraded) and retry on the watch tick,
                // never as a plain "inactive" layer.
                lock (_stateGate)
                {
                    _attachmentUnknown = true;
                    _staleProgramsAttached = true;
                    _neutralised = false;
                    _applied.Clear();
                    _generation = -1;
                }

                var reason = $"unknown: the BPF layer cannot start ({probe.Reason}) and pins of a previous daemon remain at {_paths.PinDirectory}; its programs may still be attached and enforcing verdicts of removed rules (removals pending until the layer starts)";
                Settle(false, reason);
                Log("BPF layer " + reason + ". Retrying on the next watch tick.");
                return;
            }

            if (!probe.Usable)
            {
                Settle(false, "inactive: " + probe.Reason);
                Log($"BPF layer inactive: {probe.Reason}. nftables only; the exec-time race window stays open.");
                return;
            }

            Handover? unfinished;
            lock (_stateGate)
            {
                unfinished = _handover;
            }

            if (unfinished is not null)
            {
                // A retry while an earlier start's new set is still attached unpopulated: drop that set first.
                RollBackNewSet(unfinished, "a new start attempt replaces it", markStale: false);
            }

            if (Active && _retire.Count > 0)
            {
                // The new set enforces; only the previous daemon's leftovers still need detaching. Never
                // load another set for that (no growth beyond old + new).
                RetireLeftovers();
                return;
            }

            // Startup ordering (docs/LINUX_EBPF.md §12, make-before-break): a previous daemon that crashed
            // or was restarted leaves its programs attached and pinned, and they keep refusing blocked
            // programs. They are NOT detached first: a new set is loaded next to them, populated from
            // managed-rules.json and read back (SyncAsync), and only then are the old programs detached.
            var attached = ListAttachedAxiomPrograms(out var unreadable);
            if (attached is null)
            {
                // Unknown is not "nothing attached" (PR #276 review, finding 4): loading now could put a
                // second set next to one that still enforces. Keep the pins, load nothing, retry.
                MarkUnknownAtStart(unreadable);
                return;
            }

            lock (_stateGate)
            {
                _attachmentUnknown = false;
            }

            if (attached.Count > BpfLayout.Programs.Count)
            {
                // More than one set is attached already (an earlier failure): never stack a third. Fall back
                // to detach-then-load; the window this opens is logged and documented.
                var cleared = DetachAndUnpin();
                Log($"BPF layer: {attached.Count} Axiom programs (more than one set) were attached at start; detached them before loading ({string.Join(", ", cleared.Found)}). Connect-time verdicts were not enforced until the new set was populated.");
                attached = cleared.Remaining;
                if (attached is null)
                {
                    MarkUnknownAtStart(cleared.Unreadable);
                    return;
                }

                if (attached.Count > 0)
                {
                    MarkStaleAtStart(attached);
                    return;
                }
            }

            lock (_stateGate)
            {
                _staleProgramsAttached = false;
            }

            if (attached.Count == 0)
            {
                // Nothing enforces: no hand-over needed. Clear leftover pins (a readable zero is required).
                var orphans = DetachAndUnpin();
                if (orphans.Found.Count > 0)
                {
                    Log($"BPF layer: reconciled orphaned state from a previous daemon: {string.Join(", ", orphans.Found)}.");
                }

                if (orphans.Remaining is not { Count: 0 })
                {
                    if (orphans.Remaining is null)
                    {
                        MarkUnknownAtStart(orphans.Unreadable);
                    }
                    else
                    {
                        MarkStaleAtStart(orphans.Remaining);
                    }

                    return;
                }

                if (LoadAndAttach(_paths) is { } problem)
                {
                    DetachAndUnpin();
                    Settle(false, "inactive: " + problem);
                    Log("BPF layer inactive: " + problem);
                    return;
                }

                var key = RunSelfCheck();
                lock (_stateGate)
                {
                    _applied.Clear();
                    _generation = -1;
                    _neutralised = false;
                    _kernelKey = key;
                    _activeStatus = $"active ({probe.BpftoolVersion}; programs pinned at {_paths.PinDirectory})";
                }

                Log($"BPF exe key self-check {key.State.ToString().ToLowerInvariant()}: {key.Detail}.");
                Settle(true, _activeStatus);
                Log($"BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at {_paths.CgroupRoot} (multi), pinned at {_paths.PinDirectory}.");
                return;
            }

            // Make-before-break: the previous set keeps enforcing while the new one is staged.
            var staging = _paths with { PinDirectory = StagingDirectory };
            RemovePinTree(staging.PinDirectory);
            if (LoadAndAttach(staging) is { } stagedProblem)
            {
                // The new set cannot be loaded or attached: fail closed. Drop whatever of it was attached
                // and keep the previous daemon's set enforcing, reported as stale (degraded; its maps may
                // still hold verdicts of removed rules), and retry on the next watch tick. Detaching it
                // here would open the very window this ordering exists to close.
                RollBackNewSet(new Handover(attached, []), stagedProblem, markStale: true);
                Log("BPF layer: " + stagedProblem + "; the previous daemon's programs stay attached and keep enforcing (degraded, retried on the next watch tick).");
                return;
            }

            var now = ListAttachedAxiomPrograms(out unreadable);
            if (now is null)
            {
                MarkUnknownAtStart(unreadable);
                return;
            }

            var oldIds = attached.Select(program => program.Id).ToHashSet();
            var handover = new Handover(attached, now.Where(program => !oldIds.Contains(program.Id)).Select(program => program.Id).ToList());
            var kernelKey = RunSelfCheck();
            lock (_stateGate)
            {
                _applied.Clear();
                _generation = -1;
                _neutralised = false;
                _kernelKey = kernelKey;
                _handover = handover;
                _active = false;
                _pending = true;
                _activeStatus = $"active ({probe.BpftoolVersion}; programs pinned at {_paths.PinDirectory})";
                _status = string.Create(CultureInfo.InvariantCulture, $"pending: a new program set is attached next to {attached.Count} program(s) of a previous daemon, which keep enforcing until the new maps are populated from the stored rules and read back; connect-time blocking is not verified yet");
            }

            Log($"BPF exe key self-check {kernelKey.State.ToString().ToLowerInvariant()}: {kernelKey.Detail}.");
            Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: new program set staged at {staging.PinDirectory} and attached at {_paths.CgroupRoot} next to {attached.Count} program(s) of a previous daemon ({string.Join(", ", attached.Select(program => $"{program.Name} id {program.Id}"))}); they keep enforcing until the new maps are populated and read back (make-before-break)."));
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Loads the object into <paramref name="target"/> (makes it the live pin tree) and attaches its four programs; null on success.</summary>
    private string? LoadAndAttach(BpfEnginePaths target)
    {
        var load = Run("prog", "loadall", _paths.ObjectFile, target.PinDirectory, "pinmaps", target.MapDirectory);
        if (!load.Succeeded)
        {
            return "bpftool prog loadall failed: " + Trim(load.StandardError);
        }

        _pins = target;

        // ABI 2 (24-byte exe key with the btrfs subvolume): an object built for another layout would
        // silently never match (or reject every update); refuse it and leave no pins behind.
        if (LayoutProblem() is { } layout)
        {
            return layout;
        }

        foreach (var (hook, program) in BpfLayout.Programs)
        {
            var attach = Run("cgroup", "attach", _paths.CgroupRoot, hook, "pinned", target.ProgramPin(program), "multi");
            if (!attach.Succeeded)
            {
                return $"attaching {program} at {_paths.CgroupRoot} ({hook}) failed: {Trim(attach.StandardError)}";
            }
        }

        return null;
    }

    private void MarkUnknownAtStart(string unreadable)
    {
        lock (_stateGate)
        {
            _attachmentUnknown = true;
            _staleProgramsAttached = true;
            _neutralised = false;
            _applied.Clear();
            _generation = -1;
        }

        var reason = UnknownStatus(unreadable, $"pins at {_paths.PinDirectory} kept and no new program set loaded");
        Settle(false, reason);
        Log("BPF layer " + reason + ". Retrying on the next watch tick.");
    }

    private void MarkStaleAtStart(List<(string Hook, long Id, string Name)> stale)
    {
        lock (_stateGate)
        {
            _staleProgramsAttached = true;
            _neutralised = false;
            _applied.Clear();
            _generation = -1;
        }

        var reason = string.Create(CultureInfo.InvariantCulture, $"degraded: {stale.Count} Axiom BPF program(s) of a previous daemon are still attached at {_paths.CgroupRoot} and could not be detached ({string.Join(", ", stale.Select(program => $"{program.Name} id {program.Id}"))}); their maps may still hold verdicts of removed rules, so no new set was loaded");
        Settle(false, reason);
        Log("BPF layer " + reason + ". Retrying on the next watch tick.");
    }

    /// <summary>Sets active/status and ends the starting phase.</summary>
    private void Settle(bool active, string status)
    {
        lock (_stateGate)
        {
            _active = active;
            _status = status;
            _pending = false;
        }
    }

    /// <summary>
    /// Detaches the new (staged) set and drops its pins; the previous daemon's set keeps enforcing.
    /// With <paramref name="markStale"/> the layer reports the old set as stale (degraded) and the
    /// watch tick retries the hand-over.
    /// </summary>
    private void RollBackNewSet(Handover handover, string why, bool markStale)
    {
        var staging = _paths with { PinDirectory = StagingDirectory };
        foreach (var (hook, program) in BpfLayout.Programs)
        {
            var pin = staging.ProgramPin(program);
            if (File.Exists(pin))
            {
                Run("cgroup", "detach", _paths.CgroupRoot, hook, "pinned", pin);
            }
        }

        // Anything attached that is not the previous daemon's set belongs to the new set (also when the
        // attach half-failed and its ids were never listed).
        var oldIds = handover.Old.Select(program => program.Id).ToHashSet();
        var left = ListAttachedAxiomPrograms(out _);
        foreach (var (hook, id, _) in left?.Where(program => !oldIds.Contains(program.Id)) ?? [])
        {
            Run("cgroup", "detach", _paths.CgroupRoot, hook, "id", id.ToString(CultureInfo.InvariantCulture));
        }

        left = ListAttachedAxiomPrograms(out _);
        if (left is not null && !left.Any(program => !oldIds.Contains(program.Id)))
        {
            RemovePinTree(staging.PinDirectory);
        }

        _pins = _paths;
        lock (_stateGate)
        {
            _handover = null;
            _active = false;
            _pending = false;
            _applied.Clear();
            _generation = -1;
            if (markStale)
            {
                _staleProgramsAttached = true;
                _status = string.Create(CultureInfo.InvariantCulture, $"degraded: {handover.Old.Count} program(s) of a previous daemon keep enforcing their own maps at {_paths.CgroupRoot}; the new set was rolled back because {why}; removals stay pending and the hand-over is retried on the next watch tick");
            }
        }

        Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: rolled the new program set back ({why}); {handover.Old.Count} program(s) of the previous daemon stay attached and keep enforcing."));
    }

    private enum HandoverOutcome
    {
        Done,
        Unknown,
        OldRemain,
    }

    /// <summary>The new maps are populated and read back: detach the previous set by id, then move the pins.</summary>
    private HandoverOutcome CompleteHandover(Handover handover, out string unreadable)
    {
        foreach (var (hook, id, _) in handover.Old)
        {
            Run("cgroup", "detach", _paths.CgroupRoot, hook, "id", id.ToString(CultureInfo.InvariantCulture));
        }

        var now = ListAttachedAxiomPrograms(out unreadable);
        if (now is null)
        {
            return HandoverOutcome.Unknown;
        }

        var oldIds = handover.Old.Select(program => program.Id).ToHashSet();
        var left = now.Where(program => oldIds.Contains(program.Id)).ToList();
        if (left.Count > 0)
        {
            _retire = left;
            Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: {left.Count} Axiom program(s) of the previous daemon still attached after detach ({string.Join(", ", left.Select(program => $"{program.Name} id {program.Id}"))}); the new set stays attached and enforcing; keeping {_paths.PinDirectory} as their handle and retrying on the next watch tick."));
            return HandoverOutcome.OldRemain;
        }

        // The old programs are gone from the kernel: their pins are only handles to dead objects now.
        try
        {
            RemovePinTree(_paths.PinDirectory);
            Directory.Move(StagingDirectory, _paths.PinDirectory);
            _pins = _paths;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Log($"BPF layer: could not move {StagingDirectory} to {_paths.PinDirectory} ({exception.Message}); the live set stays pinned at {StagingDirectory}.");
        }

        Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: reconciled orphaned state from a previous daemon: detached {handover.Old.Count} of its program(s) ({string.Join(", ", handover.Old.Select(program => $"{program.Name} id {program.Id}"))}) only after the new set was attached and its maps were populated and read back (make-before-break); pinned at {_pins.PinDirectory}."));
        return HandoverOutcome.Done;
    }

    /// <summary>Retries detaching a previous daemon's leftover programs; finishes the pin move once they are gone.</summary>
    private void RetireLeftovers()
    {
        foreach (var (hook, id, _) in _retire)
        {
            Run("cgroup", "detach", _paths.CgroupRoot, hook, "id", id.ToString(CultureInfo.InvariantCulture));
        }

        var now = ListAttachedAxiomPrograms(out var unreadable);
        if (now is null)
        {
            Log($"BPF layer: cannot confirm the previous daemon's leftovers are detached ({unreadable}); retrying on the next watch tick.");
            return;
        }

        var ids = _retire.Select(program => program.Id).ToHashSet();
        _retire = now.Where(program => ids.Contains(program.Id)).ToList();
        if (_retire.Count > 0)
        {
            Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: {_retire.Count} program(s) of the previous daemon still attached after detach; retrying on the next watch tick."));
            return;
        }

        try
        {
            if (Directory.Exists(StagingDirectory))
            {
                RemovePinTree(_paths.PinDirectory);
                Directory.Move(StagingDirectory, _paths.PinDirectory);
            }

            _pins = _paths;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Log($"BPF layer: could not move {StagingDirectory} to {_paths.PinDirectory} ({exception.Message}); the live set stays pinned at {StagingDirectory}.");
        }

        lock (_stateGate)
        {
            _staleProgramsAttached = false;
            _status = _activeStatus;
        }

        Log($"BPF layer: the previous daemon's leftover programs are detached; one program set remains, pinned at {_pins.PinDirectory}.");
    }

    private void RemovePinTree(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Log($"BPF layer: could not remove {directory}: {exception.Message}");
        }
    }

    public async Task<LayerSyncResult> SyncAsync(IReadOnlyList<ManagedRule> rules, long generation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rules);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Handover? handover;
            lock (_stateGate)
            {
                handover = _handover;
            }

            if (!Active && handover is null)
            {
                var inactive = LayerSyncResult.Inactive(generation, Status, Directory.Exists(_pins.PinDirectory), Neutralised) with { AttachmentUnknown = AttachmentUnknown };
                lock (_stateGate)
                {
                    _lastSync = inactive;
                }

                return inactive;
            }

            var plan = BpfVerdictPlanner.Plan(rules.Select(rule => rule.Spec), generation, _cgroups, _inodes, KernelKeyCheck);
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

            if (handover is not null)
            {
                if (failedDeletes.Count > 0 || failedUpdates.Count > 0 || !verified)
                {
                    RollBackNewSet(handover, string.Create(CultureInfo.InvariantCulture, $"its maps could not be populated and read back for generation {generation} ({string.Join("; ", failedDeletes.Concat(failedUpdates))})"), markStale: true);
                    return Remember(LayerSyncResult.Inactive(generation, Status, Directory.Exists(_pins.PinDirectory)) with { Attempts = attempts, FailedUpdates = failedUpdates.ToList(), FailedDeletes = failedDeletes.ToList() });
                }

                switch (CompleteHandover(handover, out var handoverUnreadable))
                {
                    case HandoverOutcome.Unknown:
                        lock (_stateGate)
                        {
                            _handover = null;
                            _pending = false;
                            _active = false;
                            _attachmentUnknown = true;
                            _status = UnknownStatus(handoverUnreadable, "the previous daemon's programs were asked to detach after the new set was populated; pins of both sets are kept and no further set is loaded");
                        }

                        Log($"BPF layer: cannot confirm that the previous daemon's programs were detached ({handoverUnreadable}); keeping both pin trees and retrying on the next watch tick.");
                        return Remember(LayerSyncResult.Inactive(generation, Status, true) with { AttachmentUnknown = true, Attempts = attempts });
                    case HandoverOutcome.OldRemain:
                        // The new set is populated, read back and enforcing; some of the previous daemon's
                        // programs refused to detach. Keep the new set (rolling it back would leave only the
                        // stale one), report the leftovers as stale (degraded, removals pending), keep the old
                        // pins as handles, and retry only their detach on the watch tick: no further load.
                        lock (_stateGate)
                        {
                            _handover = null;
                            _pending = false;
                            _active = true;
                            _staleProgramsAttached = true;
                            _status = string.Create(CultureInfo.InvariantCulture, $"degraded: {_retire.Count} program(s) of a previous daemon are still attached at {_paths.CgroupRoot} next to the new set and could not be detached ({string.Join(", ", _retire.Select(program => $"{program.Name} id {program.Id}"))}); their maps may still hold verdicts of removed rules; retrying the detach on the next watch tick");
                        }

                        break;
                    default:
                        lock (_stateGate)
                        {
                            _handover = null;
                            _pending = false;
                            _active = true;
                            _staleProgramsAttached = false;
                            _status = _activeStatus;
                        }

                        Log($"BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at {_paths.CgroupRoot} (multi), pinned at {_pins.PinDirectory}.");
                        break;
                }
            }

            var neutralised = false;
            if (failedDeletes.Count > 0)
            {
                // A verdict the rule set no longer wants is still in an attached map and would keep
                // blocking: the only safe move left is to stop enforcing anything from this layer.
                Log(string.Create(CultureInfo.InvariantCulture, $"BPF verdicts generation {generation}: {failedDeletes.Count} stale entr{(failedDeletes.Count == 1 ? "y" : "ies")} could not be deleted after {attempts} passes ({string.Join("; ", failedDeletes)}); neutralising: detaching Axiom's programs at {_paths.CgroupRoot} (third-party programs untouched)."));
                var detach = DetachAndUnpin();
                if (detach.Remaining is null)
                {
                    // Unknown after the detach: the stale verdict may still enforce. Never call it neutralised.
                    Log($"BPF layer: the detach is not confirmed ({detach.Unreadable}); the stale entries may still block.");
                }
                else if (detach.Remaining.Count > 0)
                {
                    // Detach failed too: the stale verdict still enforces. Say so; never pretend otherwise.
                    Log($"BPF layer: {detach.Remaining.Count} program(s) still attached after the detach ({string.Join(", ", detach.Remaining.Select(program => program.Name))}); the stale entries can still block.");
                }
                else
                {
                    neutralised = true;
                    applied.Clear();
                }
            }

            var detachedExternally = false;
            var unknown = false;
            int? attachedCount = null;
            var unreadable = string.Empty;
            if (!neutralised)
            {
                attachedCount = ProgramsAttached(out unreadable);
            }

            if (!neutralised && attachedCount is null)
            {
                unknown = true;
                Log($"BPF layer: cannot confirm whether Axiom's programs are attached at {_paths.CgroupRoot} after generation {generation} ({unreadable}); the sync is not confirmed and removals stay pending.");
            }
            else if (!neutralised && attachedCount < BpfLayout.Programs.Count)
            {
                // Someone detached Axiom's programs (bpftool cgroup detach, a cgroup tool): the maps no
                // longer enforce anything. Report it and let the watcher re-attach (Neutralised).
                detachedExternally = true;
                Log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: only {attachedCount} of {BpfLayout.Programs.Count} Axiom programs are attached at {_paths.CgroupRoot}; connect-time verdicts are not enforced until re-attached."));
            }

            var attached = !neutralised && !detachedExternally && !unknown;
            if (failedDeletes.Count > 0 && !neutralised && !unknown)
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

                _generation = failedDeletes.Count == 0 && failedUpdates.Count == 0 && !unknown ? generation : neutralised ? -1 : _generation;
                _uncovered = plan.Uncovered;
                _attachmentUnknown = unknown;
                if (unknown)
                {
                    _status = UnknownStatus(unreadable, string.Create(CultureInfo.InvariantCulture, $"generation {generation} is not confirmed{(failedDeletes.Count > 0 ? $" and {failedDeletes.Count} stale map entr{(failedDeletes.Count == 1 ? "y" : "ies")} could not be deleted" : string.Empty)}; pins and the loaded program set are kept"));
                }
                else if (attached && failedDeletes.Count == 0 && _status.StartsWith("unknown:", StringComparison.Ordinal))
                {
                    _status = _activeStatus;
                }

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
                Pinned = Directory.Exists(_pins.PinDirectory),
                Applied = attached && failedDeletes.Count == 0 && failedUpdates.Count == 0,
                Verified = attached && verified && failedDeletes.Count == 0 && failedUpdates.Count == 0,
                Neutralised = neutralised || detachedExternally,
                AttachmentUnknown = unknown,
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

    private LayerSyncResult Remember(LayerSyncResult result)
    {
        lock (_stateGate)
        {
            _lastSync = result;
        }

        return result;
    }

    public async Task StopAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (_stateGate)
            {
                _handover = null;
                _pending = false;
            }

            if (!Active && !Directory.Exists(_paths.PinDirectory) && !Directory.Exists(StagingDirectory))
            {
                // Still detach by name: a crashed daemon's programs may be attached without pins.
                DetachAndUnpin();
                SetState(false, "stopped");
                return;
            }

            var detach = DetachAndUnpin();
            lock (_stateGate)
            {
                _applied.Clear();
                _generation = -1;
                _neutralised = false;
                _kernelKey = BpfKernelKeyCheck.Unverified("layer not attached");
            }

            SetState(false, "stopped");

            // PR #276 review, finding 3: say "detached" only after a readable zero and with the pins gone.
            if (detach.Confirmed)
            {
                Log($"BPF layer detached and {_paths.PinDirectory} removed.");
            }
            else
            {
                Log(detach.Remaining is null
                    ? $"BPF layer stop: detach not confirmed ({detach.Unreadable}); {_paths.PinDirectory} kept, Axiom programs may still be attached at {_paths.CgroupRoot}."
                    : detach.Remaining.Count > 0
                        ? $"BPF layer stop: detach not confirmed: {detach.Remaining.Count} Axiom program(s) still attached at {_paths.CgroupRoot} ({string.Join(", ", detach.Remaining.Select(program => $"{program.Name} id {program.Id}"))}); {_paths.PinDirectory} kept."
                        : $"BPF layer stop: programs detached, but removing {_paths.PinDirectory} was not confirmed.");
            }
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
            var dump = Run("-j", "map", "dump", "pinned", _pins.MapPin(map));
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
        if (!File.Exists(_pins.MapPin(entry.Map)))
        {
            // ENOENT from a missing pin is not "key already gone": the map may still be attached, unpinned.
            error = $"map pin {_pins.MapPin(entry.Map)} is missing; the entry cannot be deleted or confirmed absent";
            return false;
        }

        var delete = Run(["map", "delete", "pinned", _pins.MapPin(entry.Map), "key", "hex", .. BpfLayout.HexTokens(entry.Key)]);
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
        var update = Run(["map", "update", "pinned", _pins.MapPin(entry.Map), "key", "hex", .. BpfLayout.HexTokens(entry.Key), "value", "hex", .. BpfLayout.HexTokens(entry.Value), "any"]);
        error = update.Succeeded ? string.Empty : Trim(update.StandardError);
        return update.Succeeded;
    }

    private static LayerSyncFailure Failure(string operation, BpfMapEntry entry, string error) =>
        new(operation, entry.Map, entry.KeyHex, entry.Value.Length >= 24 ? BpfLayout.ParseRuleId(Convert.ToHexStringLower(entry.Value.AsSpan(8, 16))) : null, entry.Describe, error);

    /// <summary>What <see cref="DetachAndUnpin"/> found and whether the detach is confirmed.</summary>
    /// <param name="Found">Programs detached and pins removed.</param>
    /// <param name="Remaining">Axiom programs still attached afterwards; null = unknown (bpftool unreadable).</param>
    /// <param name="Unreadable">Why the attachment state could not be read (empty when it could).</param>
    /// <param name="PinsRemoved">The pin directory is gone.</param>
    private sealed record DetachOutcome(List<string> Found, List<(string Hook, long Id, string Name)>? Remaining, string Unreadable, bool PinsRemoved)
    {
        /// <summary>A readable zero after the detach and no pin directory left.</summary>
        public bool Confirmed => Remaining is { Count: 0 } && PinsRemoved;
    }

    /// <summary>
    /// Detaches every Axiom program (by pin when pinned, else by id from <c>bpftool cgroup show</c>)
    /// and unlinks the pin tree, but only after a readable <c>cgroup show</c> lists no Axiom program:
    /// while anything is still attached, or the state cannot be read, the pins are the only handle a
    /// later detach/delete has, so they stay. Only programs named <c>axiom_*</c> are touched.
    /// </summary>
    private DetachOutcome DetachAndUnpin()
    {
        var found = new List<string>();
        var trees = new[] { _paths.PinDirectory, StagingDirectory };
        foreach (var tree in trees)
        {
            foreach (var (hook, program) in BpfLayout.Programs)
            {
                var pin = Path.Combine(tree, program);
                if (File.Exists(pin) && Run("cgroup", "detach", _paths.CgroupRoot, hook, "pinned", pin).Succeeded)
                {
                    found.Add(tree == _paths.PinDirectory ? $"pinned {program}" : $"pinned {program} ({tree})");
                }
            }
        }

        bool PinsGone() => trees.All(tree => !Directory.Exists(tree));
        var listed = ListAttachedAxiomPrograms(out var unreadable);
        if (listed is null)
        {
            Log($"BPF layer: cannot confirm the detach ({unreadable}); keeping {_paths.PinDirectory}.");
            return new DetachOutcome(found, null, unreadable, PinsGone());
        }

        foreach (var (hook, id, name) in listed)
        {
            var detach = Run("cgroup", "detach", _paths.CgroupRoot, hook, "id", id.ToString(CultureInfo.InvariantCulture));
            if (detach.Succeeded)
            {
                found.Add($"attached {name} id {id}");
            }
        }

        var remaining = ListAttachedAxiomPrograms(out unreadable);
        if (remaining is null)
        {
            Log($"BPF layer: cannot confirm the detach ({unreadable}); keeping {_paths.PinDirectory}.");
            return new DetachOutcome(found, null, unreadable, PinsGone());
        }

        if (remaining.Count > 0)
        {
            // Unlinking the pins would not detach anything; it would only take away the handles a
            // later delete/detach needs. Keep them while any Axiom program is still attached.
            Log($"BPF layer: {remaining.Count} Axiom program(s) still attached after detach; keeping {_paths.PinDirectory}.");
            return new DetachOutcome(found, remaining, string.Empty, PinsGone());
        }

        foreach (var tree in trees)
        {
            try
            {
                if (Directory.Exists(tree))
                {
                    Directory.Delete(tree, recursive: true);
                    found.Add("pins " + tree);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Log($"BPF layer: could not remove {tree}: {exception.Message}");
            }
        }

        _pins = _paths;
        _retire = [];
        return new DetachOutcome(found, remaining, string.Empty, PinsGone());
    }

    /// <summary>
    /// Number of distinct Axiom programs attached at the cgroup root, or null (unknown) when
    /// <c>bpftool cgroup show</c> failed or its output could not be read (PR #276 review, finding 4).
    /// </summary>
    private int? ProgramsAttached(out string unreadable) =>
        ListAttachedAxiomPrograms(out unreadable)?.Select(program => program.Name).Distinct(StringComparer.Ordinal).Count();

    /// <summary>Null when the loaded exe map has this daemon's key size (ABI <see cref="BpfLayout.Abi"/>), else why not.</summary>
    private string? LayoutProblem()
    {
        var show = Run("-j", "map", "show", "pinned", _pins.MapPin(BpfLayout.ExeMap));
        int? bytes = null;
        if (show.Succeeded)
        {
            try
            {
                using var document = JsonDocument.Parse(show.StandardOutput);
                if (document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty("bytes_key", out var key) && key.TryGetInt32(out var value))
                {
                    bytes = value;
                }
            }
            catch (JsonException)
            {
            }
        }

        return bytes == BpfLayout.ExeKeySize
            ? null
            : string.Create(CultureInfo.InvariantCulture, $"object key layout mismatch: {BpfLayout.ExeMap} key is {(bytes is { } size ? size + " bytes" : "unreadable (" + Trim(show.StandardError) + ")")}, this daemon writes {BpfLayout.ExeKeySize} (ABI {BpfLayout.Abi}); install the matching {BpfEnginePaths.ObjectFileName}");
    }

    /// <summary>
    /// Arms axiom_selfcheck with this process's tgid, makes one connect(), reads back the key the
    /// program computed for the daemon's own exe and compares it with the user-space key; disarms after.
    /// </summary>
    private BpfKernelKeyCheck RunSelfCheck()
    {
        var pin = _pins.MapPin(BpfLayout.SelfCheckMap);
        string[] zero = ["00", "00", "00", "00"];
        var arm = Run(["map", "update", "pinned", pin, "key", "hex", .. zero, "value", "hex", .. BpfLayout.HexTokens(BpfLayout.SelfCheckRequest(SelfPid)), "any"]);
        if (!arm.Succeeded)
        {
            return BpfKernelKeyCheck.Unverified("could not arm " + BpfLayout.SelfCheckMap + ": " + Trim(arm.StandardError));
        }

        string? connectError = null;
        try
        {
            SelfCheckConnect();
        }
        catch (Exception exception) when (exception is System.Net.Sockets.SocketException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            connectError = exception.Message;
        }

        var dump = Run("-j", "map", "dump", "pinned", pin);
        var values = dump.Succeeded ? BpfMapDump.Parse(dump.StandardOutput) : null;
        var hex = values is not null && values.TryGetValue("00000000", out var dumped) ? dumped : null;
        var record = BpfLayout.ParseSelfCheck(hex);

        // Disarm (target 0) but keep the recorded key and flags so `axiomd --doctor` can re-check them.
        var disarm = record is null || hex is null ? BpfLayout.SelfCheckRequest(0) : Convert.FromHexString(hex);
        disarm.AsSpan(0, 4).Clear();
        Run(["map", "update", "pinned", pin, "key", "hex", .. zero, "value", "hex", .. BpfLayout.HexTokens(disarm), "any"]);
        if (connectError is not null)
        {
            return BpfKernelKeyCheck.Unverified("the self-check connect() failed: " + connectError);
        }
        var real = _inodes.RealPath(SelfExePath);
        var stat = real is null ? null : _inodes.Stat(real);
        return BpfKernelKeyCheck.Compare(record, SelfPid, real ?? SelfExePath, btrfs =>
        {
            if (real is null || stat is null)
            {
                return new BpfExeKeyResolution(null, $"{SelfExePath} could not be resolved/stat'ed", null);
            }

            var mountInfo = _inodes.ReadMountInfo();
            return mountInfo is null
                ? new BpfExeKeyResolution(null, "mountinfo is unreadable", null)
                : BpfExeKey.Resolve(real, stat, MountInfoTable.Parse(mountInfo), new BpfKernelKeyCheck(BpfKernelKeyState.Verified, btrfs, "self-check candidate"), _inodes.SubvolumeId);
        });
    }

    /// <summary>Axiom's programs still attached at the cgroup root (name prefix <c>axiom_</c> as in <see cref="BpfLayout.Programs"/>).</summary>
    /// <remarks>
    /// Null means unknown: a non-zero exit, or exit 0 with output that is not the expected JSON (an
    /// invalid program id or an undecodable name included). Unknown is never "nothing attached".
    /// </remarks>
    private List<(string Hook, long Id, string Name)>? ListAttachedAxiomPrograms(out string unreadable)
    {
        var show = Run("-j", "cgroup", "show", _paths.CgroupRoot);
        if (!show.Succeeded)
        {
            unreadable = string.Create(CultureInfo.InvariantCulture, $"bpftool cgroup show {_paths.CgroupRoot} exited {show.ExitCode}: {Trim(show.StandardError)}");
            return null;
        }

        var parsed = BpfMapDump.ParseAttached(show.StandardOutput);
        if (parsed is null)
        {
            var text = Trim(show.StandardOutput);
            unreadable = $"bpftool cgroup show {_paths.CgroupRoot} printed unreadable output: {(text.Length > 80 ? text[..80] + "…" : text)}";
            return null;
        }

        unreadable = string.Empty;
        var hooks = BpfLayout.Programs.ToDictionary(program => program.Program, program => program.Hook, StringComparer.Ordinal);
        return parsed
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

    /// <summary>
    /// <c>bpftool -j cgroup show &lt;root&gt;</c>: <c>[{"id":N,"attach_type":"…","attach_flags":"multi","name":"…"}]</c>.
    /// Returns null (unknown) for anything else — output that is not a JSON array, an entry that is not an
    /// object, a missing/non-integer/non-positive program id, or a missing or non-string name or attach
    /// type that is neither a string nor a number — so a caller can never mistake unreadable output for "nothing attached" (PR #276 review,
    /// finding 4). A readable zero is <c>[]</c> or empty output: bpftool (v7.7.0 measured) prints only a
    /// newline, exit 0, for a cgroup with no programs attached.
    /// </summary>
    public static IReadOnlyList<(long Id, string Name, string AttachType)>? ParseAttached(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var programs = new List<(long, string, string)>();
            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object
                    || !element.TryGetProperty("id", out var id)
                    || id.ValueKind != JsonValueKind.Number
                    || !id.TryGetInt64(out var programId)
                    || programId is <= 0 or > uint.MaxValue // kernel program ids are nonzero uint32
                    || !element.TryGetProperty("name", out var nameElement)
                    || nameElement.ValueKind != JsonValueKind.String
                    || DecodeString(nameElement) is not { } name
                    || (element.TryGetProperty("attach_type", out var typeElement) && typeElement.ValueKind is not (JsonValueKind.String or JsonValueKind.Number)))
                {
                    return null;
                }

                // bpftool prints an attach type it has no name for as a number (a newer kernel's hook).
                var type = string.Empty;
                if (element.TryGetProperty("attach_type", out typeElement))
                {
                    if (typeElement.ValueKind == JsonValueKind.String)
                    {
                        if (DecodeString(typeElement) is not { } decoded)
                        {
                            return null;
                        }

                        type = decoded;
                    }
                    else
                    {
                        type = typeElement.GetRawText();
                    }
                }

                programs.Add((programId, name, type));
            }

            return programs;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// <see cref="JsonElement.GetString"/> throws <see cref="InvalidOperationException"/> for a correctly
    /// escaped string that is not valid UTF-16 (an unpaired surrogate): the output cannot be trusted then.
    /// </summary>
    private static string? DecodeString(JsonElement element)
    {
        try
        {
            return element.GetString();
        }
        catch (InvalidOperationException)
        {
            return null;
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
