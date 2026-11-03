// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;

namespace LocalFirewall.Infrastructure.Windows.IpHelper;

/// <summary>Formatting and byte-order helpers for the IP Helper tables. Unit tested.</summary>
internal static class EndpointFormatter
{
    /// <summary>MIB tables store ports in network byte order inside the low word of a DWORD.</summary>
    internal static ushort HostPort(uint rawPort) =>
        (ushort)(((rawPort & 0xFFu) << 8) | ((rawPort >> 8) & 0xFFu));

    internal static IPAddress Ipv4Address(uint rawAddress) =>
        new(BitConverter.GetBytes(rawAddress));

    internal static IPAddress Ipv6Address(byte[] rawAddress, uint scopeId)
    {
        ArgumentNullException.ThrowIfNull(rawAddress);
        return new IPAddress(rawAddress, (long)scopeId);
    }

    internal static string FormatEndpoint(IPAddress address, ushort port) =>
        address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";

    internal static string FormatRemote(IPAddress address, ushort port)
    {
        if (port == 0 && IsAny(address))
        {
            return "—";
        }

        return FormatEndpoint(address, port);
    }

    internal static bool IsAny(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    internal static bool IsLoopback(IPAddress address) => IPAddress.IsLoopback(address);

    internal static string StateName(uint state) => state switch
    {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => $"State {state}",
    };

    internal static bool IsListening(uint state) => state == 2;
}
