// SPDX-License-Identifier: GPL-3.0-or-later
using LocalFirewall.Contracts.Monitoring;

namespace LocalFirewall.UI.Services;

/// <summary>
/// Deterministic sample rows for the design/demo shell used when no live source is registered
/// (running LocalFirewall.UI.exe directly). Never used by the published Desktop host.
/// </summary>
public static class DemoDataFactory
{
    public const int ConnectionRowCount = 2000;

    private const int Seed = 20261101;

    private static readonly (string Host, int Port)[] RemoteEndpoints =
    [
        ("203.0.113.24", 443),
        ("198.51.100.7", 443),
        ("203.0.113.81", 443),
        ("192.0.2.55", 443),
        ("198.51.100.42", 443),
        ("203.0.113.10", 80),
        ("198.51.100.18", 443),
        ("192.0.2.12", 443),
        ("8.8.8.8", 53),
        ("1.1.1.1", 443),
    ];

    private static readonly string[] Interfaces =
    [
        "Ethernet",
        "Wi-Fi",
        "Ethernet",
        "vEthernet (WSL)",
    ];

    private static readonly DemoAppSeed[] Apps =
    [
        new("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe", 291_000_000, 412),
        new("msedge.exe", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 168_000_000, 233),
        new("Code.exe", @"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe", 41_000_000, 87),
        new("Teams.exe", @"C:\Program Files\WindowsApps\MSTeams_24193\ms-teams.exe", 96_000_000, 64),
        new("spotify.exe", @"C:\Users\dev\AppData\Roaming\Spotify\Spotify.exe", 74_000_000, 38),
        new("Discord.exe", @"C:\Users\dev\AppData\Local\Discord\app-1.0.9175\Discord.exe", 28_000_000, 41),
        new("steam.exe", @"C:\Program Files (x86)\Steam\steam.exe", 18_000_000, 19),
        new("obs64.exe", @"C:\Program Files\obs-studio\bin\64bit\obs64.exe", 1_200_000, 6),
        new("python.exe", @"C:\Users\dev\AppData\Local\Programs\Python\Python312\python.exe", 9_800_000, 52),
        new("node.exe", @"C:\Program Files\nodejs\node.exe", 6_400_000, 33),
        new("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", 11_000_000, 24),
        new("svchost.exe", @"C:\Windows\System32\svchost.exe", 3_100_000, 61),
        new("explorer.exe", @"C:\Windows\explorer.exe", 1_400_000, 17),
    ];

    public static IReadOnlyList<LiveConnection> CreateConnections()
    {
        var random = new Random(Seed);
        var weights = Apps.Select((_, index) => 14 - Math.Min(index, 11)).ToArray();
        var totalWeight = weights.Sum();
        var now = DateTimeOffset.Now;

        var rows = new List<LiveConnection>(ConnectionRowCount);

        for (var i = 0; i < ConnectionRowCount; i++)
        {
            var app = Apps[PickWeighted(random, weights, totalWeight)];
            var isUdp = random.NextDouble() < 0.18;
            var isLoopback = app.Name is "python.exe" or "node.exe" && random.NextDouble() < 0.22;
            var isInbound = !isLoopback && random.NextDouble() < 0.04;
            var isIpv6 = !isLoopback && random.NextDouble() < 0.07;

            var localPort = random.Next(49152, 65535);
            var localHost = isIpv6 ? "fe80::9c3f:4a1e:77c2:1" : "192.168.1.24";

            string remoteHost;
            int remotePort;

            if (isLoopback)
            {
                remoteHost = "127.0.0.1";
                remotePort = app.Name == "python.exe" ? 11434 : 5173;
            }
            else if (isIpv6)
            {
                remoteHost = "2606:4700:4700::1111";
                remotePort = 443;
            }
            else
            {
                var endpoint = RemoteEndpoints[random.Next(RemoteEndpoints.Length)];
                remoteHost = endpoint.Host;
                remotePort = endpoint.Port;
            }

            var state = isUdp
                ? "—"
                : isInbound
                    ? "Listen"
                    : random.NextDouble() < 0.12 ? "TimeWait" : "Established";

            var interfaceName = isLoopback
                ? "Loopback"
                : isIpv6 && !isInbound ? "Ethernet"
                : Interfaces[random.Next(Interfaces.Length)];

            var baseDownload = Math.Max(2_000, app.DownloadBytes / 900.0);
            var download = baseDownload * (0.15 + (random.NextDouble() * 1.6));
            var upload = download * (0.04 + (random.NextDouble() * 0.35));

            if (isUdp)
            {
                download *= 0.25;
                upload *= 0.4;
            }

            var quality = interfaceName == "vEthernet (WSL)" && random.NextDouble() < 0.2
                ? DataQuality.Partial
                : DataQuality.Observed;

            rows.Add(new LiveConnection
            {
                AppDisplayName = app.Name,
                AppPath = app.Path,
                ProcessId = 1000 + random.Next(0, 60000),
                Protocol = isUdp ? TransportProtocol.Udp : TransportProtocol.Tcp,
                LocalEndpoint = FormatEndpoint(localHost, localPort, isIpv6),
                RemoteEndpoint = isInbound
                    ? FormatEndpoint("198.51.100.200", random.Next(20000, 60000), isIpv6: false)
                    : FormatEndpoint(remoteHost, remotePort, isIpv6),
                State = state,
                Direction = isInbound ? ConnectionDirection.Inbound : ConnectionDirection.Outbound,
                InterfaceName = interfaceName,
                FirstObservedUtc = now.AddSeconds(-random.Next(1, 5400)),
                EstimatedUploadBytesPerSecond = Math.Round(upload, 1),
                EstimatedDownloadBytesPerSecond = Math.Round(download, 1),
                IsLoopback = isLoopback,
                IsNew = i is 7 or 42 or 311,
                RuleStatus = ConnectionRuleStatus.Unknown,
                Quality = quality,
            });
        }

        return rows;
    }

    private static string FormatEndpoint(string host, int port, bool isIpv6) =>
        isIpv6 || host.Contains(':', StringComparison.Ordinal)
            ? $"[{host}]:{port}"
            : $"{host}:{port}";

    private static int PickWeighted(Random random, int[] weights, int totalWeight)
    {
        var target = random.Next(totalWeight);
        var running = 0;
        for (var i = 0; i < weights.Length; i++)
        {
            running += weights[i];
            if (target < running)
            {
                return i;
            }
        }

        return weights.Length - 1;
    }

    private sealed record DemoAppSeed(string Name, string Path, long DownloadBytes, int Connections);
}
