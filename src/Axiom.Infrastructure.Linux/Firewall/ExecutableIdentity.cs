// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Axiom.Infrastructure.Linux.Firewall;

/// <summary>
/// Executable identity used by the eBPF policy. The kernel hashes the dentry chain of
/// <c>task->mm->exe_file</c>; userspace hashes the same filesystem-internal path. The identity is
/// namespace independent and survives PID reuse and restarts, unlike a PID, UID or cgroup id.
/// </summary>
internal sealed record ExecutableIdentity(
    ulong HashHi,
    ulong HashLo,
    string FileSystemPath,
    uint DeviceMajor = 0,
    uint DeviceMinor = 0)
{
    public const int MaxComponents = 7;

    /// <summary>Hash width and verifier mask in the BPF program (fixed 64-byte padding).</summary>
    public const int MaxNameBytes = 64;

    public byte[] KeyBytes()
    {
        var key = new byte[16];
        BitConverter.TryWriteBytes(key.AsSpan(0, 8), HashHi);
        BitConverter.TryWriteBytes(key.AsSpan(8, 8), HashLo);
        return key;
    }

    public static bool TryResolve(string appPath, out ExecutableIdentity? identity, out string? error)
    {
        identity = null;
        error = null;

        if (string.IsNullOrWhiteSpace(appPath) || !Path.IsPathFullyQualified(appPath))
        {
            error = "AppPath must be an absolute executable path.";
            return false;
        }

        if (!File.Exists(appPath))
        {
            error = "The executable path does not exist or is not a regular file.";
            return false;
        }

        string canonical;
        try
        {
            canonical = Canonicalize(appPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error = $"Cannot resolve the executable path: {exception.Message}";
            return false;
        }

        if (!File.Exists(canonical))
        {
            error = "The executable path does not exist or is not a regular file.";
            return false;
        }

        var (mountPoint, mountRoot, deviceMajor, deviceMinor) = FindMount(canonical, null);
        var fsPath = ToFileSystemPath(canonical, mountPoint, mountRoot);
        // The kernel walks d_parent, so components are hashed leaf first.
        var components = fsPath.Split('/', StringSplitOptions.RemoveEmptyEntries).Reverse().ToArray();

        if (components.Length == 0 || components.Length > MaxComponents)
        {
            error = $"Executable path depth exceeds the supported limit ({MaxComponents} components).";
            return false;
        }

        foreach (var component in components)
        {
            if (Encoding.UTF8.GetByteCount(component) >= MaxNameBytes)
            {
                error = $"An executable path component must be shorter than {MaxNameBytes} bytes.";
                return false;
            }
        }

        var (hi, lo) = HashComponents(components, deviceMajor, deviceMinor);
        identity = new ExecutableIdentity(hi, lo, fsPath, deviceMajor, deviceMinor);
        return true;
    }

    /// <summary>
    /// FNV-1a over the filesystem device and then the length plus fixed-width padded bytes of every
    /// component, leaf to root. The kernel mixes <c>d_sb->s_dev</c> first, so two filesystems that
    /// expose the same internal path do not share an identity.
    /// </summary>
    internal static (ulong Hi, ulong Lo) HashComponents(
        IReadOnlyList<string> componentsLeafToRoot,
        uint deviceMajor = 0,
        uint deviceMinor = 0)
    {
        const ulong offset = 14695981039346656037UL;
        const ulong prime = 1099511628211UL;

        var h1 = offset;
        var h2 = prime;

        h1 = (h1 ^ deviceMajor) * prime;
        h1 = (h1 ^ deviceMinor) * prime;
        h2 = (h2 ^ deviceMajor) * prime;
        h2 = (h2 << 7) | (h2 >> 57);
        h2 = (h2 ^ deviceMinor) * prime;
        h2 = (h2 << 7) | (h2 >> 57);

        // The kernel walk hashes the filesystem root dentry too, whose name is always "/".
        var ordered = componentsLeafToRoot.Append("/");

        foreach (var component in ordered)
        {
            var bytes = Encoding.UTF8.GetBytes(component);
            if (bytes.Length == 0 || bytes.Length > MaxNameBytes)
            {
                throw new ArgumentException($"Path component length is outside 1..{MaxNameBytes} bytes.", nameof(componentsLeafToRoot));
            }

            h1 ^= (ulong)bytes.Length;
            h1 *= prime;
            for (var i = 0; i < MaxNameBytes; i++)
            {
                var value = i < bytes.Length ? bytes[i] : (byte)0;
                h1 ^= value;
                h1 *= prime;
                h2 = (h2 ^ value) * prime;
                h2 = (h2 << 7) | (h2 >> 57);
            }
        }

        return (h1, h2 ^ (h1 >> 17));    }

    /// <summary>
    /// Maps a canonical path onto the path relative to its filesystem root, which is the chain the
    /// kernel walks from <c>d_parent</c>. Bind mounts and mount namespaces therefore resolve to the
    /// same identity.
    /// </summary>
    internal static string ToFileSystemPath(string canonicalPath, string? mountInfoPath = null)
    {
        var (mountPoint, root, _, _) = FindMount(canonicalPath, mountInfoPath);
        return ToFileSystemPath(canonicalPath, mountPoint, root);
    }

    private static string ToFileSystemPath(string canonicalPath, string mountPoint, string root)
    {
        var relative = canonicalPath.Length == mountPoint.Length
            ? string.Empty
            : canonicalPath[mountPoint.Length..];

        var fileSystemPath = root.TrimEnd('/') + (relative.StartsWith('/') ? relative : "/" + relative);
        if (fileSystemPath.Length == 0)
        {
            fileSystemPath = "/";
        }

        while (fileSystemPath.Contains("//", StringComparison.Ordinal))
        {
            fileSystemPath = fileSystemPath.Replace("//", "/", StringComparison.Ordinal);
        }

        return fileSystemPath.Length > 1 ? fileSystemPath.TrimEnd('/') : fileSystemPath;
    }

    private static (string MountPoint, string Root, uint Major, uint Minor) FindMount(
        string path,
        string? mountInfoPath)
    {
        var bestMountPoint = "/";
        var bestRoot = "/";
        var bestMajor = 0u;
        var bestMinor = 0u;
        var bestLength = -1;

        foreach (var line in File.ReadLines(mountInfoPath ?? "/proc/self/mountinfo"))
        {
            var fields = line.Split(' ');
            if (fields.Length < 5)
            {
                continue;
            }

            var mountPoint = Unescape(fields[4]);
            var root = Unescape(fields[3]);
            var device = fields[2].Split(':');
            if (device.Length != 2 ||
                !uint.TryParse(device[0], out var major) ||
                !uint.TryParse(device[1], out var minor))
            {
                continue;
            }

            var matches = mountPoint == "/" ||
                          path == mountPoint ||
                          path.StartsWith(mountPoint + "/", StringComparison.Ordinal);
            if (!matches || mountPoint.Length <= bestLength)
            {
                continue;
            }

            bestMountPoint = mountPoint;
            bestRoot = root;
            bestMajor = major;
            bestMinor = minor;
            bestLength = mountPoint.Length;
        }

        return (bestMountPoint, bestRoot, bestMajor, bestMinor);
    }

    private static string Unescape(string value)
    {
        if (!value.Contains('\\', StringComparison.Ordinal))
        {
            return value;
        }

        var builder = new StringBuilder(value.Length);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' &&
                i + 3 < value.Length &&
                IsOctal(value.AsSpan(i + 1, 3)))
            {
                builder.Append((char)Convert.ToInt32(value.Substring(i + 1, 3), 8));
                i += 3;
                continue;
            }

            builder.Append(value[i]);
        }

        return builder.ToString();
    }

    private static bool IsOctal(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if (character is < '0' or > '7')
            {
                return false;
            }
        }

        return true;
    }

    private static string Canonicalize(string path)
    {
        var pointer = realpath(path, IntPtr.Zero);
        if (pointer == IntPtr.Zero)
        {
            throw new IOException($"realpath failed with errno {Marshal.GetLastPInvokeError()}.");
        }

        try
        {
            return Marshal.PtrToStringUTF8(pointer) ?? path;
        }
        finally
        {
            free(pointer);
        }
    }

    [DllImport("libc", EntryPoint = "realpath", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern IntPtr realpath(string path, IntPtr resolved);

    [DllImport("libc", EntryPoint = "free")]
    private static extern void free(IntPtr pointer);
}
