// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;

namespace Axiom.Infrastructure.Linux.Monitoring;

/// <summary>One row of <c>/proc/net/{tcp,tcp6,udp,udp6}</c> joined with its owning pid (0 = unknown).</summary>
public sealed record ProcSocket(
    int ProcessId,
    bool Tcp,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    int TcpState,
    uint Uid,
    long Inode);

/// <summary>
/// Parser for the kernel socket tables. Addresses are hex in host byte order per 32-bit word
/// (<c>0100007F:0035</c> is 127.0.0.1:53); the state column is the TCP state (<c>0A</c> LISTEN).
/// Pure functions; <see cref="ProcSocketScanner"/> joins the rows with <c>/proc/&lt;pid&gt;/fd</c>.
/// </summary>
public static class ProcNetTable
{
    public const int TcpStateEstablished = 1;

    public const int TcpStateListen = 10;

    public const int TcpStateClose = 7;

    public static readonly IReadOnlyList<(string Path, bool Tcp)> Tables =
    [
        ("/proc/net/tcp", true),
        ("/proc/net/tcp6", true),
        ("/proc/net/udp", false),
        ("/proc/net/udp6", false),
    ];

    private static readonly string[] StateNames =
    [
        "Unknown", "Established", "SynSent", "SynReceived", "FinWait1", "FinWait2",
        "TimeWait", "Closed", "CloseWait", "LastAck", "Listen", "Closing", "NewSynReceived",
    ];

    public static string TcpStateName(int state) =>
        state >= 0 && state < StateNames.Length ? StateNames[state] : "State" + state.ToString(CultureInfo.InvariantCulture);

    /// <summary>Parses one table; the header and malformed rows are skipped. Pids are 0 (joined later).</summary>
    public static IReadOnlyList<ProcSocket> Parse(string text, bool tcp)
    {
        ArgumentNullException.ThrowIfNull(text);
        var sockets = new List<ProcSocket>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("sl", StringComparison.Ordinal))
            {
                continue;
            }

            var columns = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 10 ||
                !TryParseEndpoint(columns[1], out var local, out var localPort) ||
                !TryParseEndpoint(columns[2], out var remote, out var remotePort) ||
                !int.TryParse(columns[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var state) ||
                !uint.TryParse(columns[7], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ||
                !long.TryParse(columns[9], NumberStyles.None, CultureInfo.InvariantCulture, out var inode))
            {
                continue;
            }

            if (tcp && state == TcpStateClose)
            {
                continue;
            }

            sockets.Add(new ProcSocket(0, tcp, local, localPort, remote, remotePort, tcp ? state : 0, uid, inode));
        }

        return sockets;
    }

    /// <summary><c>0100007F:0035</c> → 127.0.0.1, 53; 32 hex digits → IPv6 (mapped v4 is kept as v4).</summary>
    public static bool TryParseEndpoint(string text, out IPAddress address, out int port)
    {
        address = IPAddress.None;
        port = 0;
        var colon = text.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0 ||
            !int.TryParse(text.AsSpan(colon + 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out port))
        {
            return false;
        }

        var hex = text.AsSpan(0, colon);
        if (hex.Length != 8 && hex.Length != 32)
        {
            return false;
        }

        var bytes = new byte[hex.Length / 2];
        for (var word = 0; word < bytes.Length / 4; word++)
        {
            // Each 32-bit word is written in host (little-endian) order.
            if (!uint.TryParse(hex.Slice(word * 8, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
            {
                return false;
            }

            bytes[word * 4] = (byte)value;
            bytes[(word * 4) + 1] = (byte)(value >> 8);
            bytes[(word * 4) + 2] = (byte)(value >> 16);
            bytes[(word * 4) + 3] = (byte)(value >> 24);
        }

        address = new IPAddress(bytes);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return true;
    }

    /// <summary>Parses the <c>socket:[12345]</c> target of a <c>/proc/&lt;pid&gt;/fd</c> link.</summary>
    public static bool TryParseSocketInode(string? linkTarget, out long inode)
    {
        inode = 0;
        return linkTarget is not null &&
               linkTarget.StartsWith("socket:[", StringComparison.Ordinal) &&
               linkTarget.EndsWith(']') &&
               long.TryParse(linkTarget.AsSpan(8, linkTarget.Length - 9), NumberStyles.None, CultureInfo.InvariantCulture, out inode);
    }
}
