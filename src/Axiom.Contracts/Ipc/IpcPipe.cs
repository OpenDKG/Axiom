// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Ipc;

public static class IpcPipe
{
    /// <summary>Local-only pipe name; the server applies an explicit DACL and SID check.</summary>
    public const string Name = "Axiom.Service.v1";

    /// <summary>Unix domain socket of the macOS/Linux daemon (absolute path, used as-is).</summary>
    public const string UnixSocketPath = "/var/run/axiom/axiom.sock";

    /// <summary>Overrides <see cref="UnixSocketPath"/> on Unix (development and tests).</summary>
    public const string UnixSocketVariable = "AXIOM_IPC_SOCKET";

    /// <summary>
    /// Platform endpoint: the Windows pipe name, or the daemon socket path on Unix. .NET pipe
    /// streams are Unix domain sockets on Unix and use a rooted pipe name as the socket path.
    /// </summary>
    public static string Endpoint => EndpointFor(
        OperatingSystem.IsWindows(),
        Environment.GetEnvironmentVariable(UnixSocketVariable));

    public static string EndpointFor(bool windows, string? unixOverride) =>
        windows
            ? Name
            : string.IsNullOrWhiteSpace(unixOverride) ? UnixSocketPath : unixOverride.Trim();

    /// <summary>Maps the default <see cref="Name"/> to <see cref="Endpoint"/>; explicit names pass through.</summary>
    public static string Resolve(string pipeName) =>
        string.Equals(pipeName, Name, StringComparison.Ordinal) ? Endpoint : pipeName;
}

public static class IpcErrorCodes
{
    public const string UnknownCommand = "unknown_command";
    public const string NotSupported = "not_supported";
    public const string MessageTooLarge = "message_too_large";
    public const string InvalidRequest = "invalid_request";
    public const string Unauthorized = "unauthorized";
    public const string InternalError = "internal_error";
    public const string ServiceUnavailable = "service_unavailable";
}
