// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Runtime.InteropServices;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// One AxiomFilter process: its pid plus the kernel start time (a pid alone can be reused).
/// Read from the filter's own connection to the daemon (<c>LOCAL_PEERPID</c> + libproc), so the
/// extension cannot claim another identity.
/// </summary>
public readonly record struct FilterInstanceIdentity(int ProcessId, long StartSeconds, long StartMicroseconds)
{
    public override string ToString() => string.Create(
        CultureInfo.InvariantCulture,
        $"{ProcessId}@{StartSeconds}.{StartMicroseconds:D6}");

    /// <summary>Parses <see cref="ToString"/>; null for anything else (missing or damaged marker).</summary>
    public static FilterInstanceIdentity? TryParse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var at = text.Trim().Split('@');
        if (at.Length != 2)
        {
            return null;
        }

        var start = at[1].Split('.');
        return start.Length == 2
               && int.TryParse(at[0], NumberStyles.None, CultureInfo.InvariantCulture, out var pid) && pid > 0
               && long.TryParse(start[0], NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
               && long.TryParse(start[1], NumberStyles.None, CultureInfo.InvariantCulture, out var micros)
            ? new FilterInstanceIdentity(pid, seconds, micros)
            : null;
    }

    /// <summary>Identity of the process on the other end of an accepted filter socket; null off macOS or on any failure.</summary>
    public static FilterInstanceIdentity? TryRead(System.Net.Sockets.Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (!OperatingSystem.IsMacOS() || !UnixPeerCredentials.TryGetPeerProcessId(socket, out var pid))
        {
            return null;
        }

        return LibProc.StartTime(pid) is { } start ? new FilterInstanceIdentity(pid, start.Seconds, start.Microseconds) : null;
    }
}

/// <summary>
/// Decides when mDNSResponder must be told to rebuild its sockets. macOS breaks every socket
/// that existed before a NEW content-filter instance attached; mDNSResponder keeps sending on
/// its old sockets ("Broken pipe", stalled lookups) until its configuration changes or it gets a
/// SIGHUP. So: one reset per new filter instance, never for a reconnect of the same instance or
/// a daemon restart that finds the same instance again (the last seen identity is persisted),
/// sent <c>delay</c> after the instance first connects (the breakage starts about 1.2 s after
/// startFilter), and at most once per <c>minimumInterval</c>: a second new instance inside that
/// interval moves the single pending reset, it is never dropped. Pure; no clock, no IO.
/// </summary>
public sealed class ResolverResetPolicy
{
    public static readonly TimeSpan DefaultDelay = TimeSpan.FromSeconds(5);

    public static readonly TimeSpan DefaultMinimumInterval = TimeSpan.FromSeconds(10);

    private readonly TimeSpan _delay;

    private readonly TimeSpan _minimumInterval;

    public ResolverResetPolicy(FilterInstanceIdentity? lastSeen, TimeSpan delay, TimeSpan minimumInterval)
    {
        LastSeen = lastSeen;
        _delay = delay;
        _minimumInterval = minimumInterval;
    }

    public FilterInstanceIdentity? LastSeen { get; private set; }

    public DateTimeOffset? DueAt { get; private set; }

    public DateTimeOffset? LastSent { get; private set; }

    /// <summary>Records a filter connection; true when it is a new instance (the caller persists it).</summary>
    public bool Observe(FilterInstanceIdentity identity, DateTimeOffset now)
    {
        if (LastSeen == identity)
        {
            return false;
        }

        LastSeen = identity;
        var due = now + _delay;
        if (LastSent is { } sent && due < sent + _minimumInterval)
        {
            due = sent + _minimumInterval;
        }

        DueAt = due;
        return true;
    }

    /// <summary>True exactly once when the pending reset is due; marks it sent.</summary>
    public bool TakeDue(DateTimeOffset now)
    {
        if (DueAt is not { } due || now < due)
        {
            return false;
        }

        DueAt = null;
        LastSent = now;
        return true;
    }
}

/// <summary>Result of one attempt to signal the system resolver.</summary>
public sealed record ResolverSignalResult(bool Sent, IReadOnlyList<int> ProcessIds, string Detail);

/// <summary>Sends the resolver its "rebuild sockets" signal (seam for tests).</summary>
public interface IResolverSignaller
{
    ResolverSignalResult Signal();
}

/// <summary>
/// SIGHUP to the process whose executable is exactly <see cref="ExecutablePath"/>, checked by
/// pid path (libproc), not by name, and re-checked right before the signal. No tool is executed.
/// </summary>
public sealed class MDnsResponderSignaller : IResolverSignaller
{
    public const string ExecutablePath = "/usr/sbin/mDNSResponder";

    private const int SigHup = 1;

    /// <summary>Pids whose executable path is exactly <see cref="ExecutablePath"/> (mDNSResponderHelper excluded).</summary>
    public static IReadOnlyList<int> SelectTargets(IEnumerable<int> pids, Func<int, string> pathOf)
    {
        ArgumentNullException.ThrowIfNull(pids);
        ArgumentNullException.ThrowIfNull(pathOf);
        return pids.Where(pid => pid > 1 && string.Equals(pathOf(pid), ExecutablePath, StringComparison.Ordinal)).ToArray();
    }

    public ResolverSignalResult Signal()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return new ResolverSignalResult(false, [], "not macOS");
        }

        try
        {
            var targets = SelectTargets(LibProc.ListPids(), LibProc.PidPath);
            if (targets.Count == 0)
            {
                return new ResolverSignalResult(false, [], $"no process runs {ExecutablePath}");
            }

            var sent = new List<int>();
            var errors = new List<string>();
            foreach (var pid in targets)
            {
                if (!string.Equals(LibProc.PidPath(pid), ExecutablePath, StringComparison.Ordinal))
                {
                    errors.Add(string.Create(CultureInfo.InvariantCulture, $"pid {pid} exited"));
                    continue;
                }

                if (kill(pid, SigHup) == 0)
                {
                    sent.Add(pid);
                }
                else
                {
                    errors.Add(string.Create(CultureInfo.InvariantCulture, $"kill({pid}, SIGHUP) errno {Marshal.GetLastPInvokeError()}"));
                }
            }

            return new ResolverSignalResult(sent.Count > 0, sent, errors.Count == 0 ? "ok" : string.Join("; ", errors));
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            return new ResolverSignalResult(false, [], exception.Message);
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);
}

/// <summary>
/// Daemon side of <see cref="ResolverResetPolicy"/>: reads/persists the last seen filter instance
/// (owner-only marker in the daemon's data directory), and sends the reset when due. Every
/// failure is logged and never fatal.
/// </summary>
public sealed class ResolverResetCoordinator
{
    private readonly string _markerPath;

    private readonly IResolverSignaller _signaller;

    private readonly TimeProvider _time;

    private readonly Action<string> _log;

    private readonly ResolverResetPolicy _policy;

    private readonly Lock _gate = new();

    private string _reason = string.Empty;

    public ResolverResetCoordinator(
        string markerPath,
        IResolverSignaller signaller,
        TimeProvider time,
        Action<string> log,
        TimeSpan? delay = null,
        TimeSpan? minimumInterval = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(markerPath);
        _markerPath = markerPath;
        _signaller = signaller ?? throw new ArgumentNullException(nameof(signaller));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _policy = new ResolverResetPolicy(
            ReadMarker(markerPath),
            delay ?? ResolverResetPolicy.DefaultDelay,
            minimumInterval ?? ResolverResetPolicy.DefaultMinimumInterval);
    }

    public ResolverResetPolicy Policy => _policy;

    /// <summary>Called for every accepted filter connection.</summary>
    public void FilterConnected(FilterInstanceIdentity? identity)
    {
        if (identity is not { } id)
        {
            _log("AxiomFilter connected but its process identity could not be read; no resolver reset scheduled.");
            return;
        }

        FilterInstanceIdentity? previous;
        DateTimeOffset? due;
        lock (_gate)
        {
            previous = _policy.LastSeen;
            if (!_policy.Observe(id, _time.GetUtcNow()))
            {
                return;
            }

            due = _policy.DueAt;
            _reason = previous is null
                ? $"AxiomFilter instance {id} is the first seen (no marker)"
                : $"new AxiomFilter instance {id} replaced {previous}";
        }

        try
        {
            FilterRulesFile.WriteAtomic(_markerPath, id + "\n", FilterRulesFile.PrivateMode);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _log($"Could not record the AxiomFilter instance in {_markerPath}: {exception.Message}");
        }

        _log($"{_reason}; mDNSResponder reset scheduled for {due:O}.");
    }

    /// <summary>Sends the reset when it is due; true when a signal was attempted.</summary>
    public bool Tick()
    {
        string reason;
        lock (_gate)
        {
            if (!_policy.TakeDue(_time.GetUtcNow()))
            {
                return false;
            }

            reason = _reason;
        }

        ResolverSignalResult result;
        try
        {
            result = _signaller.Signal();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            result = new ResolverSignalResult(false, [], exception.Message);
        }

        _log(result.Sent
            ? $"Sent SIGHUP to mDNSResponder (pid {string.Join(",", result.ProcessIds)}) so it rebuilds the sockets macOS broke when the filter attached ({reason})."
            : $"Could not send SIGHUP to mDNSResponder ({reason}): {result.Detail}");
        return true;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500), _time, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            Tick();
        }
    }

    private static FilterInstanceIdentity? ReadMarker(string path)
    {
        try
        {
            return File.Exists(path) ? FilterInstanceIdentity.TryParse(File.ReadAllText(path)) : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
