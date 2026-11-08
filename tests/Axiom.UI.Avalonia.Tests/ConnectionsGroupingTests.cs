// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class ConnectionsGroupingTests
{
    [Fact]
    public async Task Applications_are_grouped_with_megabytes_and_sorted_by_total_traffic()
    {
        var source = new ScriptedSource(Snapshot(
            [
                Traffic(@"C:\Apps\browser.exe", "browser.exe", 5 * 1024 * 1024, 60 * 1024 * 1024),
                Traffic(@"C:\Apps\game.exe", "game.exe", 30 * 1024 * 1024, 1 * 1024 * 1024),
            ],
            Connection(@"C:\Apps\browser.exe", "browser.exe", 42, "127.0.0.1:5000"),
            Connection(@"C:\Apps\browser.exe", "browser.exe", 43, "127.0.0.1:5001"),
            Connection(@"C:\Apps\game.exe", "game.exe", 50, "127.0.0.1:6000"),
            Connection(@"C:\Apps\tool.exe", "tool.exe", 60, "127.0.0.1:7000", sent: null, received: null)));
        var monitor = new ConnectionMonitor(source, new FakeTimerFactory());
        await monitor.PollAsync();
        var page = new ConnectionsPageViewModel(monitor);

        Assert.True(page.IsGroupedByApp);

        Assert.Equal(3, page.Groups.Count);
        Assert.Equal("browser.exe", page.Groups[0].Name);
        Assert.Equal(2, page.Groups[0].SocketCount);
        Assert.Contains("MB", page.Groups[0].TrafficText);
        Assert.Contains("5.00 MB", page.Groups[0].TrafficText);
        Assert.Contains("60.00 MB", page.Groups[0].TrafficText);

        page.GroupSort = "Sent";
        page.GroupSortDescending = false;

        Assert.Equal("browser.exe", page.Groups[0].Name);
        Assert.Equal("game.exe", page.Groups[1].Name);
        Assert.Equal("tool.exe", page.Groups[2].Name);

        page.GroupSortDescending = true;

        Assert.Equal("game.exe", page.Groups[0].Name);

        page.Dispose();
        monitor.Dispose();
    }

    [Fact]
    public async Task Groups_without_measurement_say_so_instead_of_showing_zero()
    {
        var source = new ScriptedSource(Snapshot(
            [],
            Connection(@"C:\Apps\tool.exe", "tool.exe", 7, "127.0.0.1:7000", sent: null, received: null)));
        var monitor = new ConnectionMonitor(source, new FakeTimerFactory());
        await monitor.PollAsync();
        var page = new ConnectionsPageViewModel(monitor);

        var group = Assert.Single(page.Groups);
        Assert.Equal("traffic not measured", group.TrafficText);
        Assert.False(group.HasMeasurement);

        page.Dispose();
        monitor.Dispose();
    }

    private static ConnectionSnapshot Snapshot(
        IReadOnlyList<AppTrafficTotals> traffic,
        params LiveConnection[] connections) => new()
    {
        CapturedUtc = DateTimeOffset.UnixEpoch,
        Connections = connections,
        ProcessCount = connections.Select(connection => connection.ProcessId).Distinct().Count(),
        SourceName = "test",
        AppTraffic = traffic,
    };

    private static AppTrafficTotals Traffic(
        string path,
        string name,
        long sent,
        long received) => new(
        path,
        name,
        path,
        sent,
        received,
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch);

    private static LiveConnection Connection(
        string path,
        string name,
        int pid,
        string local,
        long? sent = 1,
        long? received = 1) => new()
    {
        AppDisplayName = name,
        AppPath = path,
        ProcessId = pid,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = local,
        RemoteEndpoint = "1.1.1.1:443",
        State = "Established",
        Direction = ConnectionDirection.Outbound,
        InterfaceName = string.Empty,
        FirstObservedUtc = DateTimeOffset.UnixEpoch,
        ObservedBytesSent = sent,
        ObservedBytesReceived = received,
    };

    private sealed class ScriptedSource(ConnectionSnapshot snapshot) : IConnectionSnapshotSource
    {
        public string Name => "test";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new FakeTimer();

        private sealed class FakeTimer : IUiTimer
        {
            public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

            public bool IsEnabled { get; private set; }

            public event EventHandler? Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;

            public void StopTimer() => IsEnabled = false;

            public void Dispose() => IsEnabled = false;
        }
    }
}
