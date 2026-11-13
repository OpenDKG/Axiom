// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Infrastructure.Windows.Dns;

/// <summary>
/// Windows process facts for DNS attribution: owner pid from the IP Helper UDP/TCP owner tables,
/// parent pid from a Toolhelp snapshot, name and image path from <see cref="Process"/>.
/// </summary>
public sealed class WindowsDnsProcessLookup : IDnsProcessLookup
{
    /// <summary>Creates the shared caching attributor over the Windows lookup.</summary>
    public static IDnsAppAttributor CreateAttributor() => new ProcessDnsAppAttributor(new WindowsDnsProcessLookup());

    public int SystemProcessIdLimit => 4;

    public (string Name, string Path) Describe(int processId)
    {
        var name = string.Empty;
        var path = string.Empty;
        try
        {
            using var process = Process.GetProcessById(processId);
            name = process.ProcessName + ".exe";
            try
            {
                path = process.MainModule?.FileName ?? string.Empty;
            }
            catch (Exception exception) when (exception is
                         System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
            {
                // Protected or exiting process; the name is still useful.
            }
        }
        catch (Exception exception) when (exception is
                     ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Exited or protected process.
        }

        return (name, path);
    }

    public int ParentProcessId(int processId)
    {
        var snapshot = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == InvalidHandleValue)
        {
            return 0;
        }

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry))
            {
                return 0;
            }

            do
            {
                if (entry.ProcessId == (uint)processId)
                {
                    return (int)entry.ParentProcessId;
                }

                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return 0;
    }

    private const uint Th32CsSnapProcess = 0x00000002;

    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public int FindOwningProcess(IPEndPoint source, bool tcp)
    {
        try
        {
            if (tcp)
            {
                if (source.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    return NativeMethods.QueryTcpV6()
                        .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                                      row.State == 5 &&
                                      row.OwningPid > 4)
                        .Select(row => (int)row.OwningPid)
                        .FirstOrDefault();
                }

                return NativeMethods.QueryTcpV4()
                    .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                                  row.State == 5 &&
                                  row.OwningPid > 4)
                    .Select(row => (int)row.OwningPid)
                    .FirstOrDefault();
            }

            if (source.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return NativeMethods.QueryUdpV6()
                    .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                                  row.OwningPid > 4)
                    .Select(row => (int)row.OwningPid)
                    .FirstOrDefault();
            }

            return NativeMethods.QueryUdpV4()
                .Where(row => EndpointFormatter.HostPort(row.LocalPort) == source.Port &&
                              row.OwningPid > 4)
                .Select(row => (int)row.OwningPid)
                .FirstOrDefault();
        }
        catch (Exception exception) when (exception is
                     System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return 0;
        }
    }
}
