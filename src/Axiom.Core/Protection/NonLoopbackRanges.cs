// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Protection;

/// <summary>
/// CIDR blocks that cover every non-loopback address without touching 127.0.0.0/8 or ::1.
/// Windows Firewall block rules use these as the remote scope of the agent lockdown, so a local
/// guard on 127.0.0.1 keeps working while the agent loses internet access.
/// </summary>
public static class NonLoopbackRanges
{
    public static IReadOnlyList<string> All { get; } =
    [
        // IPv4 1.0.0.0 - 126.255.255.255 and 128.0.0.0 - 255.255.255.255.
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/3",
        "96.0.0.0/4",
        "112.0.0.0/5",
        "120.0.0.0/6",
        "124.0.0.0/7",
        "126.0.0.0/8",
        "128.0.0.0/1",

        // IPv6 global unicast, unique-local and link-local; ::1 stays reachable.
        "2000::/3",
        "fc00::/7",
        "fe80::/10",
    ];
}
