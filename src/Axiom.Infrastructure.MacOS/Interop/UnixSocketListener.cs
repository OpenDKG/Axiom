// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace Axiom.Infrastructure.MacOS.Interop;

/// <summary>Creates a listening Unix domain stream socket with an explicit file mode.</summary>
[UnsupportedOSPlatform("windows")]
internal static class UnixSocketListener
{
    public const UnixFileMode RunDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    /// <summary>0666: any local user may connect; the peer uid is checked after accept.</summary>
    public const UnixFileMode PublicSocketMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite |
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite;

    /// <summary>0600: owner (root) only.</summary>
    public const UnixFileMode PrivateSocketMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public static Socket Create(string path, UnixFileMode mode, int backlog = 16)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            var created = !Directory.Exists(directory);
            Directory.CreateDirectory(directory);
            if (created || Environment.IsPrivilegedProcess)
            {
                TrySetMode(directory, RunDirectoryMode);
            }
        }

        // A stale socket file from a previous run would make bind fail with EADDRINUSE.
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            socket.Bind(new UnixDomainSocketEndPoint(path));
            File.SetUnixFileMode(path, mode);
            socket.Listen(backlog);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Best effort; the next start removes it.
        }
    }

    private static void TrySetMode(string path, UnixFileMode mode)
    {
        try
        {
            File.SetUnixFileMode(path, mode);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Not the owner (development run); the existing mode stays.
        }
    }
}
