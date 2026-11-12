// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.Versioning;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>
/// The slice of <c>/sys/fs/cgroup</c> and <c>/proc</c> the engine needs, so cgroup placement is
/// testable with a fake. Paths are cgroup-relative (<c>axiom.slice/a-…</c>, never absolute).
/// </summary>
public interface ICgroupFs
{
    bool CgroupExists(string cgroupPath);

    /// <summary>Creates the cgroup (and parents); throws <see cref="IOException"/>/<see cref="UnauthorizedAccessException"/> on failure.</summary>
    void CreateCgroup(string cgroupPath);

    /// <summary>Removes an empty cgroup; returns false when it is still populated or missing.</summary>
    bool TryRemoveCgroup(string cgroupPath);

    IReadOnlyList<string> ListChildCgroups(string cgroupPath);

    IReadOnlyList<int> ReadProcs(string cgroupPath);

    /// <summary>Writes the pid to <c>cgroup.procs</c>; throws on EACCES/ESRCH/EBUSY.</summary>
    void MoveProcess(int pid, string cgroupPath);

    IReadOnlyList<int> ListPids();

    /// <summary>Cgroup-relative path of the process (<c>0::/…</c> line of <c>/proc/pid/cgroup</c>) or null when gone.</summary>
    string? ReadProcessCgroup(int pid);

    /// <summary>Resolved target of <c>/proc/pid/exe</c> (the kernel resolves symlinks) or null when gone/unreadable.</summary>
    string? ReadProcessExe(int pid);

    /// <summary>Canonical form of a rule's appPath: realpath when it exists, null when the path is unreachable.</summary>
    string? ResolveAppPath(string appPath);
}

/// <summary>Real cgroup v2 + procfs access for the root daemon.</summary>
[SupportedOSPlatform("linux")]
public sealed class ProcCgroupFs : ICgroupFs
{
    public const string DefaultCgroupRoot = "/sys/fs/cgroup";
    public const string DefaultProcRoot = "/proc";

    private readonly string _cgroupRoot;
    private readonly string _procRoot;

    public ProcCgroupFs(string? cgroupRoot = null, string? procRoot = null)
    {
        _cgroupRoot = string.IsNullOrWhiteSpace(cgroupRoot) ? DefaultCgroupRoot : cgroupRoot;
        _procRoot = string.IsNullOrWhiteSpace(procRoot) ? DefaultProcRoot : procRoot;
    }

    public bool CgroupExists(string cgroupPath) => Directory.Exists(Absolute(cgroupPath));

    public void CreateCgroup(string cgroupPath) => Directory.CreateDirectory(Absolute(cgroupPath));

    public bool TryRemoveCgroup(string cgroupPath)
    {
        try
        {
            // cgroup directories are removed with rmdir; they refuse while populated (EBUSY).
            Directory.Delete(Absolute(cgroupPath), recursive: false);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public IReadOnlyList<string> ListChildCgroups(string cgroupPath)
    {
        try
        {
            return Directory.EnumerateDirectories(Absolute(cgroupPath))
                .Select(dir => cgroupPath.Length == 0 ? Path.GetFileName(dir) : cgroupPath + "/" + Path.GetFileName(dir))
                .ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public IReadOnlyList<int> ReadProcs(string cgroupPath)
    {
        try
        {
            return File.ReadLines(Path.Combine(Absolute(cgroupPath), "cgroup.procs"))
                .Select(line => int.TryParse(line, out var pid) ? pid : -1)
                .Where(pid => pid > 0)
                .ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public void MoveProcess(int pid, string cgroupPath) =>
        File.WriteAllText(Path.Combine(Absolute(cgroupPath), "cgroup.procs"), pid.ToString(System.Globalization.CultureInfo.InvariantCulture));

    public IReadOnlyList<int> ListPids()
    {
        try
        {
            return Directory.EnumerateDirectories(_procRoot)
                .Select(dir => int.TryParse(Path.GetFileName(dir), out var pid) ? pid : -1)
                .Where(pid => pid > 0)
                .ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public string? ReadProcessCgroup(int pid)
    {
        try
        {
            foreach (var line in File.ReadLines(Path.Combine(_procRoot, pid.ToString(System.Globalization.CultureInfo.InvariantCulture), "cgroup")))
            {
                // cgroup v2: a single "0::/path" line.
                if (line.StartsWith("0::/", StringComparison.Ordinal))
                {
                    return line[4..];
                }
            }

            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public string? ReadProcessExe(int pid)
    {
        try
        {
            var link = new FileInfo(Path.Combine(_procRoot, pid.ToString(System.Globalization.CultureInfo.InvariantCulture), "exe"));
            var target = link.LinkTarget;
            if (string.IsNullOrEmpty(target))
            {
                return null;
            }

            const string deleted = " (deleted)";
            return target.EndsWith(deleted, StringComparison.Ordinal) ? target[..^deleted.Length] : target;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public string? ResolveAppPath(string appPath)
    {
        try
        {
            if (!File.Exists(appPath) && !Directory.Exists(appPath))
            {
                return null;
            }

            var info = new FileInfo(appPath);
            var resolved = info.ResolveLinkTarget(returnFinalTarget: true);
            return Path.GetFullPath(resolved?.FullName ?? appPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private string Absolute(string cgroupPath) =>
        cgroupPath.Length == 0 ? _cgroupRoot : Path.Combine(_cgroupRoot, cgroupPath);
}
