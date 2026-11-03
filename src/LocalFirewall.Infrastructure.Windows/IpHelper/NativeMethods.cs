// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LocalFirewall.Infrastructure.Windows.IpHelper;

/// <summary>
/// Thin, read-only wrappers around the Windows IP Helper owner tables. Two-call buffer allocation
/// is used exactly as documented for GetExtendedTcpTable/GetExtendedUdpTable.
/// </summary>
internal static class NativeMethods
{
    internal const int AfInet = 2;

    internal const int AfInet6 = 23;

    internal const int TcpTableOwnerPidAll = 5;

    internal const int UdpTableOwnerPid = 1;

    private const uint ErrorInsufficientBuffer = 122;

    [StructLayout(LayoutKind.Sequential)]
    internal struct TcpRowV4
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TcpRowV6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress;

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddress;

        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UdpRowV4
    {
        public uint LocalAddress;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UdpRowV6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress;

        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    private delegate uint QueryTableDelegate(
        IntPtr table,
        ref int size,
        bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref int size,
        bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr table,
        ref int size,
        bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    internal static List<TcpRowV4> QueryTcpV4() =>
        ReadTable<TcpRowV4>(AfInet, TcpTableOwnerPidAll, GetExtendedTcpTable);

    internal static List<TcpRowV6> QueryTcpV6() =>
        ReadTable<TcpRowV6>(AfInet6, TcpTableOwnerPidAll, GetExtendedTcpTable);

    internal static List<UdpRowV4> QueryUdpV4() =>
        ReadTable<UdpRowV4>(AfInet, UdpTableOwnerPid, GetExtendedUdpTable);

    internal static List<UdpRowV6> QueryUdpV6() =>
        ReadTable<UdpRowV6>(AfInet6, UdpTableOwnerPid, GetExtendedUdpTable);

    private static List<T> ReadTable<T>(int addressFamily, int tableClass, QueryTableDelegate query)
        where T : struct
    {
        var rows = new List<T>();
        var size = 0;

        var status = query(IntPtr.Zero, ref size, false, addressFamily, tableClass, 0);
        if (status == 0)
        {
            return rows;
        }

        if (status != ErrorInsufficientBuffer)
        {
            throw new Win32Exception((int)status);
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            status = query(buffer, ref size, false, addressFamily, tableClass, 0);
            if (status != 0)
            {
                throw new Win32Exception((int)status);
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<T>();
            var pointer = IntPtr.Add(buffer, sizeof(int));

            for (var i = 0; i < count; i++)
            {
                rows.Add(Marshal.PtrToStructure<T>(pointer));
                pointer = IntPtr.Add(pointer, rowSize);
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
