// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.MacOS.Interop;

/// <summary>
/// Effective uid of the process on the other end of a connected Unix domain socket:
/// <c>getpeereid(2)</c> on macOS/BSD, <c>SO_PEERCRED</c> on Linux (development and CI).
/// </summary>
internal static class UnixPeerCredentials
{
    private const int SolSocketLinux = 1;

    private const int SoPeerCredLinux = 17;

    public static bool TryGetPeerUid(Socket socket, out uint uid)
    {
        ArgumentNullException.ThrowIfNull(socket);
        uid = uint.MaxValue;

        try
        {
            var fd = (int)socket.Handle;
            if (OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD())
            {
                if (getpeereid(fd, out var peerUid, out _) != 0)
                {
                    return false;
                }

                uid = peerUid;
                return true;
            }

            if (OperatingSystem.IsLinux())
            {
                var credentials = default(UCred);
                var length = Marshal.SizeOf<UCred>();
                if (getsockopt(fd, SolSocketLinux, SoPeerCredLinux, ref credentials, ref length) != 0)
                {
                    return false;
                }

                uid = credentials.Uid;
                return true;
            }
        }
        catch (Exception exception) when (exception is
                     DllNotFoundException or EntryPointNotFoundException or ObjectDisposedException)
        {
            return false;
        }

        return false;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UCred
    {
        public int Pid;
        public uint Uid;
        public uint Gid;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getpeereid(int socket, out uint euid, out uint egid);

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(int socket, int level, int optionName, ref UCred optionValue, ref int optionLength);
}
