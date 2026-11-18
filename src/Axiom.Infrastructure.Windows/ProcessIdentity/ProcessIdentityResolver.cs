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
    bool IsResolved)
{
    public int? ParentProcessId { get; init; }

    public string ParentProcessName { get; init; } = string.Empty;

    public string ParentChain { get; init; } = string.Empty;

    /// <summary>Sanitised command line, or empty when WMI cannot expose it.</summary>
    public string CommandLine { get; init; } = string.Empty;

    /// <summary>Authenticode signer subject, or empty when unsigned/unreadable.</summary>
    public string SignerName { get; init; } = string.Empty;

    /// <summary>Valid, Untrusted, Unsigned or Unavailable.</summary>
    public string SignatureStatus { get; init; } = "Unavailable";

    public string ProductName { get; init; } = string.Empty;

    public string FileVersion { get; init; } = string.Empty;

    /// <summary>Windows service names hosted by this process, usually only for svchost.exe.</summary>
    public string HostedServices { get; init; } = string.Empty;

    /// <summary>Windows service names hosted by the immediate parent, when it is svchost.exe.</summary>
    public string ParentHostedServices { get; init; } = string.Empty;
}

/// <summary>
/// Resolves PID to executable name/path with a short-lived cache. Access denied and protected
/// processes are reported as unresolved instead of inventing a path. No elevation is requested.
/// </summary>
public sealed class ProcessIdentityResolver
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int MaxCacheEntries = 512;

    private readonly Dictionary<int, CachedIdentity> _cache = [];
    private readonly Lock _gate = new();
    private readonly TimeSpan _cacheLifetime = TimeSpan.FromSeconds(30);
    private readonly ProcessMetadataProvider _metadata = new();

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
            if (_cache.Count >= MaxCacheEntries)
            {
                PruneCacheLocked(now);
            }

            _cache[processId] = new CachedIdentity(identity, now);
        }

        return identity;
    }

    private void PruneCacheLocked(DateTimeOffset now)
    {
        List<int>? expired = null;
        foreach (var pair in _cache)
        {
            if (now - pair.Value.ResolvedUtc >= _cacheLifetime)
            {
                (expired ??= []).Add(pair.Key);
            }
        }

        if (expired is not null)
        {
            foreach (var key in expired)
            {
                _cache.Remove(key);
            }
        }

        if (_cache.Count < MaxCacheEntries)
        {
            return;
        }

        // Fall back to evicting oldest quarter when PID churn exceeds MaxCacheEntries within TTL.
        var toRemove = _cache.Count - (MaxCacheEntries * 3 / 4);
        foreach (var key in _cache.OrderBy(static pair => pair.Value.ResolvedUtc).Take(toRemove).Select(static pair => pair.Key).ToList())
        {
            _cache.Remove(key);
        }
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

    private ProcessIdentityInfo Query(int processId)
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
            return WithMetadata(new ProcessIdentityInfo(processId, fileName, path, true), processId, path);
        }

        var processName = TryQueryProcessName(processId);
        if (!string.IsNullOrEmpty(processName))
        {
            return WithMetadata(
                new ProcessIdentityInfo(processId, $"{processName}.exe", string.Empty, false),
                processId,
                string.Empty);
        }

        return WithMetadata(
            new ProcessIdentityInfo(processId, $"PID {processId}", string.Empty, false),
            processId,
            string.Empty);
    }

    private ProcessIdentityInfo WithMetadata(
        ProcessIdentityInfo identity,
        int processId,
        string path)
    {
        var metadata = _metadata.Resolve(processId, path);
        return identity with
        {
            ParentProcessId = metadata.ParentProcessId,
            ParentProcessName = metadata.ParentProcessName,
            ParentChain = metadata.ParentChain,
            CommandLine = metadata.CommandLine,
            SignerName = metadata.SignerName,
            SignatureStatus = metadata.SignatureStatus,
            ProductName = metadata.ProductName,
            FileVersion = metadata.FileVersion,
            HostedServices = metadata.HostedServices,
            ParentHostedServices = metadata.ParentHostedServices,
        };
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
