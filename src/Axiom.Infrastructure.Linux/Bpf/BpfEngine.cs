// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
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
/// </summary>
public sealed class BpfEngine : IEnforcementLayer, IDisposable
{
    public static readonly TimeSpan DefaultEventsRestartDelay = TimeSpan.FromSeconds(2);

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
    private long _generation = -1;
    private IReadOnlyList<BpfUncoveredRule> _uncovered = [];

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

    /// <summary>Generation of the last successful map sync, -1 before the first.</summary>
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

            if (Directory.Exists(_paths.PinDirectory))
            {
                Log($"BPF layer: stale pins at {_paths.PinDirectory} from a previous daemon; detaching and removing them.");
                DetachAndUnpin();
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
            }

            SetState(true, $"active ({probe.BpftoolVersion}; programs pinned at {_paths.PinDirectory})");
            Log($"BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at {_paths.CgroupRoot} (multi), pinned at {_paths.PinDirectory}.");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SyncAsync(IReadOnlyList<ManagedRule> rules, long generation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rules);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!Active)
            {
                return;
            }

            var plan = BpfVerdictPlanner.Plan(rules.Select(rule => rule.Spec), generation, _cgroups, _inodes);
            var desired = plan.Entries.ToDictionary(entry => entry.Map + ":" + entry.KeyHex, StringComparer.Ordinal);
            var failures = new List<string>();
            Dictionary<string, BpfMapEntry> applied;
            lock (_stateGate)
            {
                applied = new Dictionary<string, BpfMapEntry>(_applied, StringComparer.Ordinal);
            }

            foreach (var (id, stale) in applied.Where(pair => !desired.ContainsKey(pair.Key)).ToList())
            {
                var delete = Run(["map", "delete", "pinned", _paths.MapPin(stale.Map), "key", "hex", .. BpfLayout.HexTokens(stale.Key)]);
                if (delete.Succeeded || delete.StandardError.Contains("No such", StringComparison.OrdinalIgnoreCase))
                {
                    applied.Remove(id);
                }
                else
                {
                    failures.Add($"delete {stale.Describe}: {Trim(delete.StandardError)}");
                }
            }

            foreach (var (id, entry) in desired)
            {
                var update = Run(["map", "update", "pinned", _paths.MapPin(entry.Map), "key", "hex", .. BpfLayout.HexTokens(entry.Key), "value", "hex", .. BpfLayout.HexTokens(entry.Value), "any"]);
                if (update.Succeeded)
                {
                    applied[id] = entry;
                }
                else
                {
                    failures.Add($"update {entry.Describe}: {Trim(update.StandardError)}");
                }
            }

            lock (_stateGate)
            {
                _applied.Clear();
                foreach (var (id, entry) in applied)
                {
                    _applied[id] = entry;
                }

                _generation = failures.Count == 0 ? generation : _generation;
                _uncovered = plan.Uncovered;
            }

            Log(string.Create(
                CultureInfo.InvariantCulture,
                $"BPF verdicts generation {generation}: {plan.ExeEntries} exe, {plan.CgroupEntries} cgroup entries; {plan.Uncovered.Count} rule(s) left to nftables{(failures.Count == 0 ? "." : "; " + failures.Count + " map write(s) failed: " + string.Join("; ", failures))}"));
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
                SetState(false, "stopped");
                return;
            }

            DetachAndUnpin();
            lock (_stateGate)
            {
                _applied.Clear();
                _generation = -1;
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

    /// <summary>Detaches every program (errors ignored: it may not be attached) and unlinks the pin tree.</summary>
    private void DetachAndUnpin()
    {
        foreach (var (hook, program) in BpfLayout.Programs)
        {
            var pin = _paths.ProgramPin(program);
            if (File.Exists(pin))
            {
                Run("cgroup", "detach", _paths.CgroupRoot, hook, "pinned", pin);
            }
        }

        try
        {
            if (Directory.Exists(_paths.PinDirectory))
            {
                Directory.Delete(_paths.PinDirectory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Log($"BPF layer: could not remove {_paths.PinDirectory}: {exception.Message}");
        }
    }

    private ProcessResult Run(params string[] arguments) => Run((IReadOnlyList<string>)arguments);

    private ProcessResult Run(IReadOnlyList<string> arguments) => _runner.Run(BpfCapabilityProbe.Bpftool, arguments, Timeout);

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
