// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Axiom.Infrastructure.MacOS.Interop;

/// <summary>An Internet socket owned by a process, read from libproc.</summary>
public sealed record LibProcSocket(
    int ProcessId,
    bool Tcp,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    int TcpState);

/// <summary>Subset of <c>struct proc_bsdinfo</c>.</summary>
public sealed record LibProcBsdInfo(int ProcessId, int ParentProcessId, uint Uid, string Command, string Name);

/// <summary>
/// Pure decoders for the libproc structures (xnu bsd/sys/proc_info.h, LP64 layout identical on
/// x86_64 and arm64). Kept separate from the P/Invoke so they are unit-tested on any OS.
/// </summary>
public static class LibProcLayout
{
    public const int SocketFdInfoBufferSize = 1024;

    public const int BsdInfoSize = 136;

    public const int ProcFdInfoSize = 8;

    public const int ProxFdTypeSocket = 2;

    public const int AfInet = 2;

    public const int AfInet6 = 30;

    public const int SockInfoIn = 1;

    public const int SockInfoTcp = 2;

    public const int IpProtoTcp = 6;

    public const int IpProtoUdp = 17;

    public const int TcpStateListen = 1;

    // struct socket_fdinfo { struct proc_fileinfo pfi (24 bytes); struct socket_info psi; }
    internal const int SocketInfoOffset = 24;

    internal const int SoiProtocolOffset = SocketInfoOffset + 156;

    internal const int SoiFamilyOffset = SocketInfoOffset + 160;

    internal const int SoiKindOffset = SocketInfoOffset + 232;

    internal const int InSockInfoOffset = SocketInfoOffset + 240;

    internal const int InsiForeignPortOffset = InSockInfoOffset + 0;

    internal const int InsiLocalPortOffset = InSockInfoOffset + 4;

    internal const int InsiVflagOffset = InSockInfoOffset + 24;

    internal const int InsiForeignAddressOffset = InSockInfoOffset + 32;

    internal const int InsiLocalAddressOffset = InSockInfoOffset + 48;

    // struct tcp_sockinfo { struct in_sockinfo tcpsi_ini (80 bytes); int tcpsi_state; ... }
    internal const int TcpStateOffset = InSockInfoOffset + 80;

    internal const int MinimumSocketBytes = TcpStateOffset + 4;

    private const byte IniIpv4 = 0x1;

    private const byte IniIpv6 = 0x2;

    /// <summary>Decodes a <c>PROC_PIDFDSOCKETINFO</c> buffer; null for non-Internet sockets.</summary>
    public static LibProcSocket? ParseSocketFdInfo(int processId, ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < MinimumSocketBytes)
        {
            return null;
        }

        var family = BinaryPrimitives.ReadInt32LittleEndian(buffer[SoiFamilyOffset..]);
        if (family != AfInet && family != AfInet6)
        {
            return null;
        }

        var kind = BinaryPrimitives.ReadInt32LittleEndian(buffer[SoiKindOffset..]);
        if (kind != SockInfoIn && kind != SockInfoTcp)
        {
            return null;
        }

        var protocol = BinaryPrimitives.ReadInt32LittleEndian(buffer[SoiProtocolOffset..]);
        var tcp = kind == SockInfoTcp || protocol == IpProtoTcp;
        if (!tcp && protocol != IpProtoUdp)
        {
            return null;
        }

        var vflag = buffer[InsiVflagOffset];
        var ipv4 = (vflag & IniIpv4) != 0 && (vflag & IniIpv6) == 0;
        var local = ReadAddress(buffer[InsiLocalAddressOffset..], ipv4);
        var remote = ReadAddress(buffer[InsiForeignAddressOffset..], ipv4);

        return new LibProcSocket(
            processId,
            tcp,
            local,
            NetworkPort(BinaryPrimitives.ReadInt32LittleEndian(buffer[InsiLocalPortOffset..])),
            remote,
            NetworkPort(BinaryPrimitives.ReadInt32LittleEndian(buffer[InsiForeignPortOffset..])),
            kind == SockInfoTcp ? BinaryPrimitives.ReadInt32LittleEndian(buffer[TcpStateOffset..]) : -1);
    }

    public static LibProcBsdInfo? ParseBsdInfo(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < BsdInfoSize)
        {
            return null;
        }

        return new LibProcBsdInfo(
            (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer[12..]),
            (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer[16..]),
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[20..]),
            CString(buffer.Slice(48, 16)),
            CString(buffer.Slice(64, 32)));
    }

    /// <summary>
    /// <c>pbi_start_tvsec</c>/<c>pbi_start_tvusec</c> (offsets 120/128 of <c>struct proc_bsdinfo</c>):
    /// the process start time, which together with the pid identifies one process instance.
    /// </summary>
    public static (long Seconds, long Microseconds)? ParseStartTime(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < BsdInfoSize)
        {
            return null;
        }

        var seconds = (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer[120..]);
        var micros = (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer[128..]);
        return seconds > 0 ? (seconds, micros) : null;
    }

    /// <summary>Decodes the <c>struct proc_fdinfo</c> array from <c>PROC_PIDLISTFDS</c>.</summary>
    public static IEnumerable<int> SocketDescriptors(byte[] buffer, int length)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        for (var offset = 0; offset + ProcFdInfoSize <= Math.Min(length, buffer.Length); offset += ProcFdInfoSize)
        {
            var fd = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset));
            var type = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset + 4));
            if (type == ProxFdTypeSocket)
            {
                yield return fd;
            }
        }
    }

    public static string TcpStateName(int state) => state switch
    {
        0 => "Closed",
        1 => "Listen",
        2 => "SynSent",
        3 => "SynReceived",
        4 => "Established",
        5 => "CloseWait",
        6 => "FinWait1",
        7 => "Closing",
        8 => "LastAck",
        9 => "FinWait2",
        10 => "TimeWait",
        _ => "State " + state.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    /// <summary>libproc stores the network-order <c>in_port_t</c> widened to int.</summary>
    internal static int NetworkPort(int raw) => BinaryPrimitives.ReverseEndianness((ushort)(raw & 0xFFFF));

    private static IPAddress ReadAddress(ReadOnlySpan<byte> field, bool ipv4) =>
        ipv4 ? new IPAddress(field.Slice(12, 4)) : new IPAddress(field[..16]);

    private static string CString(ReadOnlySpan<byte> bytes)
    {
        var end = bytes.IndexOf((byte)0);
        return Encoding.UTF8.GetString(end >= 0 ? bytes[..end] : bytes);
    }
}

/// <summary>P/Invoke into libproc (part of libSystem on macOS).</summary>
[SupportedOSPlatform("macos")]
public static class LibProc
{
    private const string Library = "/usr/lib/libproc.dylib";

    private const uint ProcAllPids = 1;

    private const int ProcPidListFds = 1;

    private const int ProcPidTBsdInfo = 3;

    private const int ProcPidFdSocketInfo = 3;

    private const int PathMax = 4096;

    public static int[] ListPids()
    {
        var needed = proc_listpids(ProcAllPids, 0, null, 0);
        if (needed <= 0)
        {
            return [];
        }

        // Processes may start between the two calls; leave headroom.
        var buffer = new int[(needed / sizeof(int)) + 64];
        var bytes = proc_listpids(ProcAllPids, 0, buffer, buffer.Length * sizeof(int));
        if (bytes <= 0)
        {
            return [];
        }

        return buffer.Take(bytes / sizeof(int)).Where(pid => pid > 0).Distinct().ToArray();
    }

    public static string PidPath(int pid)
    {
        var buffer = new byte[PathMax];
        var length = proc_pidpath(pid, buffer, (uint)buffer.Length);
        return length > 0 ? Encoding.UTF8.GetString(buffer, 0, length) : string.Empty;
    }

    public static LibProcBsdInfo? BsdInfo(int pid)
    {
        var buffer = new byte[LibProcLayout.BsdInfoSize];
        var bytes = proc_pidinfo(pid, ProcPidTBsdInfo, 0, buffer, buffer.Length);
        return bytes >= LibProcLayout.BsdInfoSize ? LibProcLayout.ParseBsdInfo(buffer) : null;
    }

    public static (long Seconds, long Microseconds)? StartTime(int pid)
    {
        var buffer = new byte[LibProcLayout.BsdInfoSize];
        var bytes = proc_pidinfo(pid, ProcPidTBsdInfo, 0, buffer, buffer.Length);
        return bytes >= LibProcLayout.BsdInfoSize ? LibProcLayout.ParseStartTime(buffer) : null;
    }

    public static IReadOnlyList<LibProcSocket> Sockets(int pid)
    {
        var needed = proc_pidinfo(pid, ProcPidListFds, 0, null, 0);
        if (needed <= 0)
        {
            return [];
        }

        var fds = new byte[needed + (32 * LibProcLayout.ProcFdInfoSize)];
        var bytes = proc_pidinfo(pid, ProcPidListFds, 0, fds, fds.Length);
        if (bytes <= 0)
        {
            return [];
        }

        var result = new List<LibProcSocket>();
        var info = new byte[LibProcLayout.SocketFdInfoBufferSize];
        foreach (var fd in LibProcLayout.SocketDescriptors(fds, bytes))
        {
            var read = proc_pidfdinfo(pid, fd, ProcPidFdSocketInfo, info, info.Length);
            if (read < LibProcLayout.MinimumSocketBytes)
            {
                continue;
            }

            if (LibProcLayout.ParseSocketFdInfo(pid, info.AsSpan(0, read)) is { } socket)
            {
                result.Add(socket);
            }
        }

        return result;
    }

    [DllImport(Library, SetLastError = true)]
    private static extern int proc_listpids(uint type, uint typeinfo, [Out] int[]? buffer, int buffersize);

    [DllImport(Library, SetLastError = true)]
    private static extern int proc_pidpath(int pid, [Out] byte[] buffer, uint buffersize);

    [DllImport(Library, SetLastError = true)]
    private static extern int proc_pidinfo(int pid, int flavor, ulong arg, [Out] byte[]? buffer, int buffersize);

    [DllImport(Library, SetLastError = true)]
    private static extern int proc_pidfdinfo(int pid, int fd, int flavor, [Out] byte[] buffer, int buffersize);
}
