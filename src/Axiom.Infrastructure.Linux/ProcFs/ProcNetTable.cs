// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Monitoring;

namespace Axiom.Infrastructure.Linux.ProcFs;

/// <summary>One row of a Linux <c>/proc/net</c> socket table.</summary>
public sealed record ProcSocketRow(
    TransportProtocol Protocol,
    IPAddress LocalAddress,
    ushort LocalPort,
    IPAddress? RemoteAddress,
    ushort RemotePort,
    string State,
    long Inode,
    int SocketUid);

/// <summary>
/// Parser for <c>/proc/net/{tcp,tcp6,udp,udp6}</c>. The kernel writes addresses as 32-bit words in
/// host byte order and ports in network order; the parser is byte-order explicit so it behaves the
/// same on a big-endian host. Malformed rows are skipped, never guessed.
/// </summary>
public static class ProcNetTable
{
    public static IReadOnlyList<ProcSocketRow> Parse(string content, bool ipv6, TransportProtocol protocol)
    {
        ArgumentNullException.ThrowIfNull(content);

        var rows = new List<ProcSocketRow>();

        foreach (var line in content.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith("sl", StringComparison.Ordinal))
            {
                continue;
            }

            var columns = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 10)
            {
                continue;
            }

            if (!TryParseEndpoint(columns[1], ipv6, out var localAddress, out var localPort) ||
                !TryParseEndpoint(columns[2], ipv6, out var remoteAddress, out var remotePort))
            {
                continue;
            }

            if (!uint.TryParse(columns[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var stateNumber))
            {
                continue;
            }

            _ = long.TryParse(columns[9], NumberStyles.None, CultureInfo.InvariantCulture, out var inode);
            _ = int.TryParse(columns[7], NumberStyles.None, CultureInfo.InvariantCulture, out var uid);

            rows.Add(new ProcSocketRow(
                protocol,
                localAddress,
                localPort,
                remoteAddress,
                remotePort,
                StateName(stateNumber),
                inode,
                uid));
        }

        return rows;
    }

    public static string StateName(uint state) => state switch
    {
        0x01 => "Established",
        0x02 => "SynSent",
        0x03 => "SynReceived",
        0x04 => "FinWait1",
        0x05 => "FinWait2",
        0x06 => "TimeWait",
        0x07 => "Closed",
        0x08 => "CloseWait",
        0x09 => "LastAck",
        0x0A => "Listen",
        0x0B => "Closing",
        0x0C => "NewSynReceived",
        _ => $"State 0x{state:X2}",
    };

    public static bool IsListening(string state) =>
        string.Equals(state, "Listen", StringComparison.Ordinal);

    private static bool TryParseEndpoint(
        string value,
        bool ipv6,
        out IPAddress address,
        out ushort port)
    {
        address = IPAddress.None;
        port = 0;

        var separator = value.LastIndexOf(':');
        if (separator <= 0 || separator == value.Length - 1)
        {
            return false;
        }

        var addressText = value[..separator];
        var portText = value[(separator + 1)..];

        if (!ushort.TryParse(portText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out port))
        {
            return false;
        }

        var expectedLength = ipv6 ? 32 : 8;
        if (addressText.Length != expectedLength)
        {
            return false;
        }

        try
        {
            address = ipv6 ? ParseIpv6(addressText) : ParseIpv4(addressText);
            return true;
        }
        catch (Exception exception) when (exception is FormatException or OverflowException or ArgumentException)
        {
            return false;
        }
    }

    private static IPAddress ParseIpv4(string hex)
    {
        var value = uint.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return new IPAddress(new[]
        {
            (byte)(value & 0xFF),
            (byte)((value >> 8) & 0xFF),
            (byte)((value >> 16) & 0xFF),
            (byte)((value >> 24) & 0xFF),
        });
    }

    private static IPAddress ParseIpv6(string hex)
    {
        var bytes = new byte[16];

        for (var group = 0; group < 4; group++)
        {
            var word = uint.Parse(
                hex.AsSpan(group * 8, 8),
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture);
            var offset = group * 4;
            bytes[offset] = (byte)(word & 0xFF);
            bytes[offset + 1] = (byte)((word >> 8) & 0xFF);
            bytes[offset + 2] = (byte)((word >> 16) & 0xFF);
            bytes[offset + 3] = (byte)((word >> 24) & 0xFF);
        }

        return new IPAddress(bytes);
    }
}
