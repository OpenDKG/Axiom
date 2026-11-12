// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.Monitoring;

/// <summary>
/// Socket inventory from <c>/proc</c>: the four kernel tables joined with the
/// <c>socket:[inode]</c> links under <c>/proc/&lt;pid&gt;/fd</c>. Walking every fd table is the
/// expensive part, so the scan is cached for <see cref="Lifetime"/> and shared by the Connections
/// poll and the Privacy Shield DNS attributor (the Linux counterpart of
/// <c>LibProcSocketScanner.Shared</c>); a lookup miss may <see cref="Refresh"/> no more than
/// every <see cref="RefreshFloor"/>. Without root (or CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH) only the
/// daemon user's fd tables are readable, and other users' sockets stay at pid 0.
/// </summary>
public sealed class ProcSocketScanner
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(2);

    public static readonly TimeSpan RefreshFloor = TimeSpan.FromMilliseconds(500);

    private readonly Func<IReadOnlyList<ProcSocket>> _scan;

    private readonly TimeProvider _time;

    private readonly object _gate = new();

    private IReadOnlyList<ProcSocket> _sockets = [];

    private DateTimeOffset _scannedUtc = DateTimeOffset.MinValue;

    private long _passes;

    public ProcSocketScanner(Func<IReadOnlyList<ProcSocket>> scan, TimeProvider time)
    {
        _scan = scan ?? throw new ArgumentNullException(nameof(scan));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <summary>The process-wide scanner over the real <c>/proc</c>.</summary>
    public static ProcSocketScanner Shared { get; } = new(() => Scan("/proc"), TimeProvider.System);

    public long Passes => Interlocked.Read(ref _passes);

    public IReadOnlyList<ProcSocket> Current() => Get(refresh: false);

    public IReadOnlyList<ProcSocket> Refresh() => Get(refresh: true);

    /// <summary>One full pass over <paramref name="procRoot"/> (tests point it at a fake tree).</summary>
    public static IReadOnlyList<ProcSocket> Scan(string procRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(procRoot);
        var rows = new List<ProcSocket>();
        foreach (var (path, tcp) in ProcNetTable.Tables)
        {
            var file = Path.Combine(procRoot, path.TrimStart('/').Replace("proc/", string.Empty, StringComparison.Ordinal));
            if (!File.Exists(file))
            {
                continue;
            }

            try
            {
                rows.AddRange(ProcNetTable.Parse(File.ReadAllText(file), tcp));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // A table that vanished mid-read (network namespace teardown) is skipped this pass.
            }
        }

        if (rows.Count == 0)
        {
            return rows;
        }

        var owners = MapInodes(procRoot, rows.Select(row => row.Inode).ToHashSet());
        for (var index = 0; index < rows.Count; index++)
        {
            if (owners.TryGetValue(rows[index].Inode, out var pid))
            {
                rows[index] = rows[index] with { ProcessId = pid };
            }
        }

        return rows;
    }

    /// <summary>inode → pid for the inodes of interest, reading every readable <c>/proc/&lt;pid&gt;/fd</c>.</summary>
    public static Dictionary<long, int> MapInodes(string procRoot, IReadOnlySet<long> inodes)
    {
        ArgumentNullException.ThrowIfNull(inodes);
        var owners = new Dictionary<long, int>();
        IEnumerable<string> processDirectories;
        try
        {
            processDirectories = Directory.EnumerateDirectories(procRoot);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return owners;
        }

        foreach (var directory in processDirectories)
        {
            if (!int.TryParse(Path.GetFileName(directory), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            IEnumerable<string> descriptors;
            try
            {
                descriptors = Directory.EnumerateFileSystemEntries(Path.Combine(directory, "fd"));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            try
            {
                foreach (var descriptor in descriptors)
                {
                    string? target;
                    try
                    {
                        target = new FileInfo(descriptor).LinkTarget;
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                        continue;
                    }

                    if (ProcNetTable.TryParseSocketInode(target, out var inode) && inodes.Contains(inode))
                    {
                        owners.TryAdd(inode, pid);
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // The process exited while its fd table was being listed.
            }
        }

        return owners;
    }

    private IReadOnlyList<ProcSocket> Get(bool refresh)
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
}
