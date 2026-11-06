// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Axiom.Infrastructure.Windows.ProcessIdentity;

/// <summary>Best-effort identity of the process that owns a socket.</summary>
public sealed record ProcessIdentityInfo(
    int ProcessId,
    string DisplayName,
    string ExecutablePath,
    bool IsResolved);

/// <summary>
/// Resolves PID to executable name/path with a short-lived cache. Access denied and protected
/// processes are reported as unresolved instead of inventing a path. No elevation is requested.
/// </summary>
public sealed class ProcessIdentityResolver
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    private readonly Dictionary<int, CachedIdentity> _cache = [];
    private readonly Lock _gate = new();
    private readonly TimeSpan _cacheLifetime = TimeSpan.FromSeconds(30);

    public ProcessIdentityInfo Resolve(int processId)
    {
        var now = DateTimeOffset.UtcNow;

        lock (_gate)
        {
            if (_cache.TryGetValue(processId, out var cached) &&
                now - cached.ResolvedUtc < _cacheLifetime)
            {
                return cached.Identity;
            }
        }

        var identity = Query(processId);

        lock (_gate)
        {
            _cache[processId] = new CachedIdentity(identity, now);
        }

        return identity;
    }

    public void Clear()
    {
        lock (_gate)
        {
            _cache.Clear();
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        [Out] char[] executableName,
        ref int size);

    private static ProcessIdentityInfo Query(int processId)
    {
        if (processId == 0)
        {
            return new ProcessIdentityInfo(0, "System · unowned (PID 0)", string.Empty, false);
        }

        if (processId == 4)
        {
            return new ProcessIdentityInfo(4, "System", string.Empty, false);
        }

        var path = TryQueryImagePath(processId);
        if (!string.IsNullOrEmpty(path))
        {
            var fileName = Path.GetFileName(path);
            return new ProcessIdentityInfo(processId, fileName, path, true);
        }

        var processName = TryQueryProcessName(processId);
        if (!string.IsNullOrEmpty(processName))
        {
            return new ProcessIdentityInfo(processId, $"{processName}.exe", string.Empty, false);
        }

        return new ProcessIdentityInfo(processId, $"PID {processId}", string.Empty, false);
    }

    private static string? TryQueryImagePath(int processId)
    {
        try
        {
            using var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
            if (handle.IsInvalid)
            {
                return null;
            }

            var buffer = new char[1024];
            var size = buffer.Length;
            return QueryFullProcessImageName(handle, 0, buffer, ref size)
                ? new string(buffer, 0, size)
                : null;
        }
        catch (Win32Exception)
        {
            return null;
        }
    }

    private static string? TryQueryProcessName(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (Win32Exception)
        {
            return null;
        }
    }

    private sealed record CachedIdentity(ProcessIdentityInfo Identity, DateTimeOffset ResolvedUtc);
}
