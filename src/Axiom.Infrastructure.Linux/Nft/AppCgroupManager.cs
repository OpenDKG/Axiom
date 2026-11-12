// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>What kind of cgroup a process was found in before Axiom moved it.</summary>
public enum SourceCgroupKind
{
    /// <summary>Already in the Axiom cgroup for its app.</summary>
    AxiomOwned = 0,

    /// <summary>A per-app systemd scope under a user session (<c>app-….scope</c>, <c>vte-spawn-….scope</c>, transient <c>run-….scope</c>).</summary>
    AppScope = 1,

    /// <summary>A user session leaf (<c>session-N.scope</c>, a user service): shared with the shell that launched the app.</summary>
    UserSessionLeaf = 2,

    /// <summary>A system service or the init scope: moving breaks the unit's accounting; done but reported.</summary>
    SystemService = 3,

    /// <summary>Anything else (containers, unknown hierarchies).</summary>
    Other = 4,
}

/// <summary>One attribution decision: a pid matched an app and was (or was not) placed in its cgroup.</summary>
public sealed record CgroupPlacement(
    int Pid,
    string ExePath,
    string AppPath,
    string SourceCgroup,
    SourceCgroupKind SourceKind,
    string TargetCgroup,
    bool Moved,
    string? Error)
{
    /// <summary>True when the move deserves a user-visible note (system service pids are moved but reported).</summary>
    public bool Reportable => Error is not null || SourceKind == SourceCgroupKind.SystemService;
}

/// <summary>Result of one attribution pass.</summary>
public sealed record AttributionReport(IReadOnlyList<CgroupPlacement> Placements, IReadOnlyList<string> RemovedCgroups);

/// <summary>
/// Owns <c>/sys/fs/cgroup/axiom.slice</c>: one cgroup per application path
/// (<c>axiom.slice/a-&lt;16 hex of sha256(path)&gt;</c>) that every rule for that app is keyed on.
/// A process can only be in one cgroup, so the cgroup is per app, not per rule; rules for the same
/// app share it. Processes whose <c>/proc/pid/exe</c> equals the app path (or lies inside it when the
/// app path is a directory) are moved into it by writing <c>cgroup.procs</c>.
/// <para>
/// Herding policy (plan section 9): a pid is moved regardless of where it lives, because the spike
/// proved an already-running process is only matched once it is inside the keyed cgroup; the kind
/// of source cgroup is classified and system-service moves are reported so the daemon can surface
/// them. Pids that cannot be moved (EACCES, ESRCH, a kernel thread) are reported as errors, and a
/// rule whose app has at least one unmovable live process is rejected by the adapter.
/// </para>
/// </summary>
public sealed class AppCgroupManager : IAppCgroupResolver
{
    public const string DefaultSlice = "axiom.slice";

    private readonly ICgroupFs _fs;
    private readonly string _slice;
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _apps = new(StringComparer.Ordinal);
    private readonly Dictionary<int, string> _origins = [];

    public AppCgroupManager(ICgroupFs fs, string? slice = null)
    {
        _fs = fs ?? throw new ArgumentNullException(nameof(fs));
        _slice = string.IsNullOrWhiteSpace(slice) ? DefaultSlice : slice.Trim('/');
    }

    public string Slice => _slice;

    public IReadOnlyList<int> ReadProcs(string cgroupPath) => _fs.ReadProcs(cgroupPath);

    /// <summary>Whether the cgroup directory exists right now (the enforcement check behind "Applied").</summary>
    public bool Exists(string cgroupPath) => !string.IsNullOrEmpty(cgroupPath) && _fs.CgroupExists(cgroupPath);

    /// <summary>Apps currently keyed (canonical app path → cgroup path).</summary>
    public IReadOnlyDictionary<string, string> Apps
    {
        get
        {
            lock (_gate)
            {
                return new Dictionary<string, string>(_apps, StringComparer.Ordinal);
            }
        }
    }

    public static string CgroupNameFor(string canonicalAppPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalAppPath);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalAppPath));
        return "a-" + Convert.ToHexStringLower(hash.AsSpan(0, 8));
    }

    /// <summary>Resolves (and creates when needed) the cgroup for a rule's app; see <see cref="IAppCgroupResolver"/>.</summary>
    public bool TryResolve(string appPath, out string cgroupPath, out string reason)
    {
        cgroupPath = string.Empty;
        reason = string.Empty;
        var canonical = _fs.ResolveAppPath(appPath);
        if (canonical is null)
        {
            reason = $"appPath is not reachable on this system: {appPath}";
            return false;
        }

        var path = _slice + "/" + CgroupNameFor(canonical);
        try
        {
            if (!_fs.CgroupExists(path))
            {
                _fs.CreateCgroup(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            reason = $"cannot create cgroup {path}: {exception.Message}";
            return false;
        }

        lock (_gate)
        {
            _apps[canonical] = path;
        }

        cgroupPath = path;
        return true;
    }

    /// <summary>Forgets apps that no longer have rules, so their cgroups are pruned on the next pass.</summary>
    public void Retain(IEnumerable<string> appPaths)
    {
        ArgumentNullException.ThrowIfNull(appPaths);
        var keep = new HashSet<string>(StringComparer.Ordinal);
        foreach (var app in appPaths)
        {
            if (_fs.ResolveAppPath(app) is { } canonical)
            {
                keep.Add(canonical);
            }
        }

        lock (_gate)
        {
            foreach (var app in _apps.Keys.Where(app => !keep.Contains(app)).ToList())
            {
                _apps.Remove(app);
            }
        }
    }

    /// <summary>
    /// One pass: scans every pid, moves matching processes into their app cgroup and removes empty
    /// Axiom cgroups that belong to no keyed app. Safe to run every second (one readlink per pid).
    /// </summary>
    public AttributionReport Attribute()
    {
        Dictionary<string, string> apps;
        lock (_gate)
        {
            apps = new Dictionary<string, string>(_apps, StringComparer.Ordinal);
        }

        var placements = new List<CgroupPlacement>();
        if (apps.Count > 0)
        {
            foreach (var pid in _fs.ListPids())
            {
                var exe = _fs.ReadProcessExe(pid);
                if (exe is null)
                {
                    continue;
                }

                var app = MatchApp(exe, apps.Keys);
                if (app is null)
                {
                    continue;
                }

                var target = apps[app];
                var source = _fs.ReadProcessCgroup(pid) ?? string.Empty;
                if (string.Equals(source, target, StringComparison.Ordinal))
                {
                    continue;
                }

                var kind = Classify(source);
                try
                {
                    _fs.MoveProcess(pid, target);
                    lock (_gate)
                    {
                        // Remember where it came from so the pid can be returned when its rules go away.
                        if (kind != SourceCgroupKind.AxiomOwned)
                        {
                            _origins[pid] = source;
                        }
                    }

                    placements.Add(new CgroupPlacement(pid, exe, app, source, kind, target, true, null));
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    placements.Add(new CgroupPlacement(pid, exe, app, source, kind, target, false, exception.Message));
                }
            }
        }

        var removed = new List<string>();
        var live = new HashSet<string>(apps.Values, StringComparer.Ordinal);
        foreach (var child in _fs.ListChildCgroups(_slice))
        {
            if (!live.Contains(child))
            {
                // The app has no rules any more: give its processes back, then drop the cgroup.
                ReleaseProcesses(child);
                if (_fs.ReadProcs(child).Count == 0 && _fs.TryRemoveCgroup(child))
                {
                    removed.Add(child);
                }
            }
        }

        return new AttributionReport(placements, removed);
    }

    /// <summary>
    /// Moves every process of an Axiom cgroup back to where it came from: the recorded origin when
    /// the daemon moved it (and the cgroup still exists), else its parent's cgroup (children were
    /// forked inside the Axiom cgroup, or the daemon restarted), else the cgroup root.
    /// </summary>
    public IReadOnlyList<CgroupPlacement> ReleaseProcesses(string cgroupPath)
    {
        ArgumentNullException.ThrowIfNull(cgroupPath);
        var released = new List<CgroupPlacement>();
        foreach (var pid in _fs.ReadProcs(cgroupPath))
        {
            string? origin;
            lock (_gate)
            {
                _origins.Remove(pid, out origin);
            }

            if (origin is null || !_fs.CgroupExists(origin))
            {
                origin = null;
                var parent = _fs.ReadParentPid(pid);
                if (parent is { } ppid && _fs.ReadProcessCgroup(ppid) is { } parentCgroup &&
                    !parentCgroup.StartsWith(_slice + "/", StringComparison.Ordinal) && parentCgroup != _slice)
                {
                    origin = parentCgroup;
                }
            }

            origin ??= string.Empty;
            var exe = _fs.ReadProcessExe(pid) ?? string.Empty;
            try
            {
                _fs.MoveProcess(pid, origin);
                released.Add(new CgroupPlacement(pid, exe, string.Empty, cgroupPath, SourceCgroupKind.AxiomOwned, origin, true, null));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                released.Add(new CgroupPlacement(pid, exe, string.Empty, cgroupPath, SourceCgroupKind.AxiomOwned, origin, false, exception.Message));
            }
        }

        return released;
    }

    /// <summary>Existing app cgroups under <c>axiom.slice</c> (only that slice is ever listed).</summary>
    public IReadOnlyList<string> ListSliceCgroups() =>
        _fs.CgroupExists(_slice) ? _fs.ListChildCgroups(_slice) : [];

    /// <summary>Returns every herded process and removes every Axiom cgroup (daemon shutdown / uninstall).</summary>
    public IReadOnlyList<string> RemoveAll()
    {
        lock (_gate)
        {
            _apps.Clear();
        }

        var removed = new List<string>();
        foreach (var child in _fs.ListChildCgroups(_slice))
        {
            ReleaseProcesses(child);
            if (_fs.ReadProcs(child).Count == 0 && _fs.TryRemoveCgroup(child))
            {
                removed.Add(child);
            }
        }

        if (_fs.CgroupExists(_slice) && _fs.ListChildCgroups(_slice).Count == 0 && _fs.TryRemoveCgroup(_slice))
        {
            removed.Add(_slice);
        }

        return removed;
    }

    /// <summary>Case-sensitive match: exact path, or inside the app path when it is a directory prefix.</summary>
    public static string? MatchApp(string exePath, IEnumerable<string> canonicalAppPaths)
    {
        ArgumentNullException.ThrowIfNull(exePath);
        ArgumentNullException.ThrowIfNull(canonicalAppPaths);
        string? best = null;
        foreach (var app in canonicalAppPaths)
        {
            if (string.Equals(exePath, app, StringComparison.Ordinal))
            {
                return app;
            }

            if (exePath.StartsWith(app.TrimEnd('/') + "/", StringComparison.Ordinal) && (best is null || app.Length > best.Length))
            {
                best = app;
            }
        }

        return best;
    }

    public SourceCgroupKind Classify(string cgroupPath)
    {
        ArgumentNullException.ThrowIfNull(cgroupPath);
        if (cgroupPath.StartsWith(_slice + "/", StringComparison.Ordinal))
        {
            return SourceCgroupKind.AxiomOwned;
        }

        var leaf = cgroupPath[(cgroupPath.LastIndexOf('/') + 1)..];
        var inUser = cgroupPath.StartsWith("user.slice/", StringComparison.Ordinal);
        if (inUser &&
            ((leaf.EndsWith(".scope", StringComparison.Ordinal) &&
              (leaf.StartsWith("app-", StringComparison.Ordinal) ||
               leaf.StartsWith("vte-spawn-", StringComparison.Ordinal) ||
               leaf.StartsWith("run-", StringComparison.Ordinal))) ||
             cgroupPath.Contains("/app.slice/", StringComparison.Ordinal)))
        {
            return SourceCgroupKind.AppScope;
        }

        if (inUser)
        {
            return SourceCgroupKind.UserSessionLeaf;
        }

        if (cgroupPath.Length == 0 || cgroupPath == "init.scope" || cgroupPath.StartsWith("system.slice", StringComparison.Ordinal))
        {
            return SourceCgroupKind.SystemService;
        }

        return SourceCgroupKind.Other;
    }

    /// <summary>Human-readable summary line for logs/notes.</summary>
    public static string Describe(CgroupPlacement placement)
    {
        ArgumentNullException.ThrowIfNull(placement);
        return placement.Moved
            ? string.Create(CultureInfo.InvariantCulture, $"pid {placement.Pid} ({placement.ExePath}) moved from {placement.SourceKind} cgroup {placement.SourceCgroup} into {placement.TargetCgroup}")
            : string.Create(CultureInfo.InvariantCulture, $"pid {placement.Pid} ({placement.ExePath}) could not be moved from {placement.SourceCgroup} into {placement.TargetCgroup}: {placement.Error}");
    }
}
