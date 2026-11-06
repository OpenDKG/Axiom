// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Ipc;

/// <summary>
/// Resolves the local IPC endpoint. Windows uses the named pipe from <see cref="IpcPipe"/>; Unix
/// hosts use a filesystem socket whose parent directory is private. The explicit override exists
/// for isolated test runs and for services installed outside the default locations.
/// </summary>
public static class IpcEndpoint
{
    public const string SocketPathVariable = "AXIOM_IPC_SOCKET";

    public static string SystemSocketPath => "/run/axiom/service.sock";

    public static bool UsesUnixSocket => !OperatingSystem.IsWindows();

    /// <summary>Client-side path: explicit override, then the system install, then the user runtime path.</summary>
    public static string ResolveClientUnixSocketPath()
    {
        var configured = Environment.GetEnvironmentVariable(SocketPathVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        return File.Exists(SystemSocketPath) ? SystemSocketPath : ResolveUserUnixSocketPath();
    }

    /// <summary>
    /// Server-side path. A service running as root defaults to <c>/run/axiom</c>; anything else
    /// stays inside the invoking user's runtime directory.
    /// </summary>
    public static string ResolveServerUnixSocketPath()
    {
        var configured = Environment.GetEnvironmentVariable(SocketPathVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Unix sockets are not used on Windows.");
        }

        if (PosixIdentity.IsSuperUser)
        {
            return SystemSocketPath;
        }

        return ResolveUserUnixSocketPath();
    }

    private static string ResolveUserUnixSocketPath()
    {
        var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        var root = string.IsNullOrWhiteSpace(runtime)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom",
                "run")
            : Path.Combine(runtime, "axiom");

        return Path.Combine(root, "service.sock");
    }
}
