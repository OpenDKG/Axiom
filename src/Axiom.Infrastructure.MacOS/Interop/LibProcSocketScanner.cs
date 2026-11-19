// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.Versioning;

namespace Axiom.Infrastructure.MacOS.Interop;

/// <summary>
/// One shared pass over the libproc socket table (<c>proc_listpids</c> + per-pid
/// <c>PROC_PIDLISTFDS</c> + per-fd <c>PROC_PIDFDSOCKETINFO</c>, i.e. thousands of syscalls per
/// pass) for every consumer. Review #10: the connection fallback polled every second and the DNS
/// attributor scanned again on its own clock, so two full scans ran per second. Now a pass is
/// reused for <see cref="Lifetime"/> (2 s); a consumer that misses an entry (a socket created after
/// the pass) may ask for a refresh, but at most once per <see cref="RefreshFloor"/> (500 ms), so a
/// burst of unknown queries costs one extra pass, not one per query.
/// </summary>
public sealed class LibProcSocketScanner
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(2);

    public static readonly TimeSpan RefreshFloor = TimeSpan.FromMilliseconds(500);

    private readonly Func<IReadOnlyList<LibProcSocket>> _scan;

    private readonly TimeProvider _time;

    private readonly object _gate = new();

    private IReadOnlyList<LibProcSocket> _sockets = [];

    private DateTimeOffset _scannedUtc = DateTimeOffset.MinValue;

    private long _passes;

    public LibProcSocketScanner(Func<IReadOnlyList<LibProcSocket>> scan, TimeProvider time)
    {
        _scan = scan ?? throw new ArgumentNullException(nameof(scan));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <summary>The process-wide scanner over the real libproc (macOS only).</summary>
    [SupportedOSPlatform("macos")]
    public static LibProcSocketScanner Shared { get; } = new(ScanLibProc, TimeProvider.System);

    /// <summary>Number of full passes made so far (tests measure sharing with this).</summary>
    public long Passes => Interlocked.Read(ref _passes);

    /// <summary>The current table; a new pass only when the cached one is older than <see cref="Lifetime"/>.</summary>
    public IReadOnlyList<LibProcSocket> Current() => Get(refresh: false);

    /// <summary>
    /// A fresher table for a consumer that found no match: a new pass unless one was made within
    /// <see cref="RefreshFloor"/>.
    /// </summary>
    public IReadOnlyList<LibProcSocket> Refresh() => Get(refresh: true);

    private IReadOnlyList<LibProcSocket> Get(bool refresh)
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            var age = now - _scannedUtc;
            if (age >= (refresh ? RefreshFloor : Lifetime))
            {
                _sockets = _scan();
                _scannedUtc = now;
                Interlocked.Increment(ref _passes);
            }

            return _sockets;
        }
    }

    [SupportedOSPlatform("macos")]
    private static List<LibProcSocket> ScanLibProc()
    {
        var result = new List<LibProcSocket>();
        foreach (var pid in LibProc.ListPids())
        {
            result.AddRange(LibProc.Sockets(pid));
        }

        return result;
    }
}
