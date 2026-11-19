// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Axiom.Infrastructure.Windows.IpHelper;

/// <summary>Cumulative TCP payload bytes for one connection, from Windows extended TCP statistics.</summary>
internal readonly record struct TcpByteCounts(long Sent, long Received);

/// <summary>
/// Reads cumulative per-connection TCP byte counters. Collection must be enabled once per
/// connection (requires elevation); enabling resets that connection's counters, so the reader
/// remembers tuples it has already enabled. UDP has no equivalent and returns null.
/// </summary>
internal sealed class TcpConnectionByteReader : IDisposable
{
    private const int TcpConnectionEstatsData = 1;

    private const uint ErrorAccessDenied = 5;

    private const uint ErrorNotFound = 1168;

    private readonly object _gate = new();

    private readonly Dictionary<string, byte> _enabled = new(StringComparer.Ordinal);

    private readonly Dictionary<string, DateTimeOffset> _failed = new(StringComparer.Ordinal);

    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    // One reusable 64-byte row buffer; MIB_TCP6ROW is 52 bytes and MIB_TCPROW is 20 bytes.
    // Wrapped in a SafeHandle so the unmanaged allocation is reliably freed on GC even without explicit disposal.
    private readonly NativeRowBuffer _row = new(64);

    private bool _unavailable;

    public bool IsUnavailable
    {
        get
        {
            lock (_gate)
            {
                return _unavailable;
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _row.Dispose();
        }
    }

    public void BeginCapture()
    {
        lock (_gate)
        {
            _seen.Clear();
        }
    }

    public void EndCapture()
    {
        lock (_gate)
        {
            foreach (var key in _enabled.Keys.Where(key => !_seen.Contains(key)).ToList())
            {
                _enabled.Remove(key);
            }

            foreach (var key in _failed.Keys.Where(key => !_seen.Contains(key)).ToList())
            {
                _failed.Remove(key);
            }
        }
    }

    public TcpByteCounts? TryRead(in NativeMethods.TcpRowV4 row)
    {
        lock (_gate)
        {
            if (_unavailable || _row.IsClosed || _row.IsInvalid)
            {
                return null;
            }

            var key = string.Create(
                CultureInfo.InvariantCulture,
                $"v4|{row.LocalAddress:x8}:{EndpointFormatter.HostPort(row.LocalPort)}|" +
                $"{row.RemoteAddress:x8}:{EndpointFormatter.HostPort(row.RemotePort)}");
            _seen.Add(key);
            WriteV4(row);
            return Read(key, ipv6: false);
        }
    }

    public TcpByteCounts? TryRead(in NativeMethods.TcpRowV6 row)
    {
        lock (_gate)
        {
            if (_unavailable || _row.IsClosed || _row.IsInvalid)
            {
                return null;
            }

            var key = string.Create(
                CultureInfo.InvariantCulture,
                $"v6|{Convert.ToHexString(row.LocalAddress)}:{EndpointFormatter.HostPort(row.LocalPort)}|" +
                $"{Convert.ToHexString(row.RemoteAddress)}:{EndpointFormatter.HostPort(row.RemotePort)}");
            _seen.Add(key);
            WriteV6(row);
            return Read(key, ipv6: true);
        }
    }

    private TcpByteCounts? Read(string key, bool ipv6)
    {
        if (!EnsureEnabled(key, ipv6))
        {
            return null;
        }

        var rod = default(TcpEstatsDataRod);
        var status = ipv6
            ? GetPerTcp6ConnectionEStats(
                _row.DangerousGetHandle(),
                TcpConnectionEstatsData,
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                0,
                0,
                ref rod,
                0,
                (uint)Marshal.SizeOf<TcpEstatsDataRod>())
            : GetPerTcpConnectionEStats(
                _row.DangerousGetHandle(),
                TcpConnectionEstatsData,
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                0,
                0,
                ref rod,
                0,
                (uint)Marshal.SizeOf<TcpEstatsDataRod>());

        if (status == ErrorNotFound)
        {
            // The connection closed between the owner-table read and this call.
            _enabled.Remove(key);
            return null;
        }

        if (status != 0)
        {
            return null;
        }

        return new TcpByteCounts(Clamp(rod.DataBytesOut), Clamp(rod.DataBytesIn));
    }

    private bool EnsureEnabled(string key, bool ipv6)
    {
        if (_enabled.ContainsKey(key))
        {
            return true;
        }

        var now = DateTimeOffset.UtcNow;
        if (_failed.TryGetValue(key, out var retryAt) && retryAt > now)
        {
            return false;
        }

        var rw = new TcpEstatsDataRw { EnableCollection = 1 };
        var status = ipv6
            ? SetPerTcp6ConnectionEStats(_row.DangerousGetHandle(), TcpConnectionEstatsData, ref rw, 0, 1, 0)
            : SetPerTcpConnectionEStats(_row.DangerousGetHandle(), TcpConnectionEstatsData, ref rw, 0, 1, 0);

        if (status == 0)
        {
            _enabled.Add(key, 0);
            _failed.Remove(key);
            return true;
        }

        _failed[key] = now.AddMinutes(5);
        if (status == ErrorAccessDenied)
        {
            // A non-elevated run cannot enable collection; do not retry for every connection.
            _unavailable = true;
        }

        return false;
    }

    private void WriteV4(in NativeMethods.TcpRowV4 row)
    {
        var buffer = _row.DangerousGetHandle();
        Marshal.WriteInt32(buffer, 0, unchecked((int)row.State));
        Marshal.WriteInt32(buffer, 4, unchecked((int)row.LocalAddress));
        Marshal.WriteInt32(buffer, 8, unchecked((int)row.LocalPort));
        Marshal.WriteInt32(buffer, 12, unchecked((int)row.RemoteAddress));
        Marshal.WriteInt32(buffer, 16, unchecked((int)row.RemotePort));
    }

    private void WriteV6(in NativeMethods.TcpRowV6 row)
    {
        var buffer = _row.DangerousGetHandle();
        Marshal.Copy(row.LocalAddress, 0, buffer, 16);
        Marshal.WriteInt32(buffer, 16, unchecked((int)row.LocalScopeId));
        Marshal.WriteInt32(buffer, 20, unchecked((int)row.LocalPort));
        Marshal.Copy(row.RemoteAddress, 0, IntPtr.Add(buffer, 24), 16);
        Marshal.WriteInt32(buffer, 40, unchecked((int)row.RemoteScopeId));
        Marshal.WriteInt32(buffer, 44, unchecked((int)row.RemotePort));
        Marshal.WriteInt32(buffer, 48, unchecked((int)row.State));
    }

    private sealed class NativeRowBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public NativeRowBuffer(int size)
            : base(ownsHandle: true)
        {
            SetHandle(Marshal.AllocHGlobal(size));
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    private static long Clamp(ulong value) => value > long.MaxValue ? long.MaxValue : (long)value;

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpEstatsDataRw
    {
        public byte EnableCollection;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpEstatsDataRod
    {
        public ulong DataBytesOut;
        public ulong DataSegsOut;
        public ulong DataBytesIn;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrors;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcpConnectionEStats(
        IntPtr row,
        int type,
        IntPtr rw,
        uint rwVersion,
        uint rwSize,
        IntPtr ros,
        uint rosVersion,
        uint rosSize,
        ref TcpEstatsDataRod rod,
        uint rodVersion,
        uint rodSize);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcp6ConnectionEStats(
        IntPtr row,
        int type,
        IntPtr rw,
        uint rwVersion,
        uint rwSize,
        IntPtr ros,
        uint rosVersion,
        uint rosSize,
        ref TcpEstatsDataRod rod,
        uint rodVersion,
        uint rodSize);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcpConnectionEStats(
        IntPtr row,
        int type,
        ref TcpEstatsDataRw rw,
        uint rwVersion,
        uint rwSize,
        uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcp6ConnectionEStats(
        IntPtr row,
        int type,
        ref TcpEstatsDataRw rw,
        uint rwVersion,
        uint rwSize,
        uint offset);
}
