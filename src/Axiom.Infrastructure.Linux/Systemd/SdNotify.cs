// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Text;

namespace Axiom.Infrastructure.Linux.Systemd;

/// <summary>
/// Minimal <c>sd_notify(3)</c>: one datagram per state to the socket named by
/// <c>$NOTIFY_SOCKET</c> (a path, or an abstract name starting with <c>@</c>). No native
/// dependency; silently a no-op when the daemon was not started by systemd with
/// <c>Type=notify</c>. The unit uses <c>NotifyAccess=main</c>, so only the daemon's own pid may send.
/// </summary>
public static class SdNotify
{
    public const string SocketVariable = "NOTIFY_SOCKET";

    public const string Ready = "READY=1";

    public const string Stopping = "STOPPING=1";

    /// <summary>True when systemd expects notifications from this process.</summary>
    public static bool IsEnabled => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(SocketVariable));

    /// <summary>Sends <paramref name="state"/> (e.g. <c>READY=1</c>); returns false when not under systemd or on error.</summary>
    public static bool Send(string state) => Send(state, Environment.GetEnvironmentVariable(SocketVariable));

    public static bool Send(string state, string? notifySocket)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(state);
        if (string.IsNullOrEmpty(notifySocket))
        {
            return false;
        }

        try
        {
            using var socket = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
            var endpoint = new UnixDomainSocketEndPoint(AbstractToPath(notifySocket));
            var payload = Encoding.UTF8.GetBytes(state.EndsWith('\n') ? state : state + "\n");
            return socket.SendTo(payload, endpoint) == payload.Length;
        }
        catch (Exception exception) when (exception is SocketException or ArgumentException or IOException)
        {
            return false;
        }
    }

    /// <summary><c>STATUS=&lt;text&gt;</c> shown by <c>systemctl status</c>.</summary>
    public static bool Status(string text) => Send("STATUS=" + (text ?? string.Empty).Replace('\n', ' '));

    /// <summary>systemd spells an abstract socket with a leading <c>@</c>; the kernel wants a NUL byte.</summary>
    internal static string AbstractToPath(string notifySocket) =>
        notifySocket.StartsWith('@') ? "\0" + notifySocket[1..] : notifySocket;
}
