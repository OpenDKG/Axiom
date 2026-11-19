// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Ipc;
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
        Assert.Equal("now idle", page.Groups[0].RateText);

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

    [Fact]
    public async Task Expanded_group_survives_refresh_and_shows_the_latest_rate()
    {
        var path = @"C:\Apps\browser.exe";
        var source = new ScriptedSource(Snapshot(
            [Traffic(path, "browser.exe", 5 * 1024 * 1024, 60 * 1024 * 1024, 1_500_000, 3_000_000)],
            Connection(path, "browser.exe", 42, "127.0.0.1:5000")));
        var monitor = new ConnectionMonitor(source, new FakeTimerFactory());
        await monitor.PollAsync();
        var page = new ConnectionsPageViewModel(monitor);
        var group = Assert.Single(page.Groups);
        group.IsExpanded = true;

        source.Snapshot = Snapshot(
            [Traffic(path, "browser.exe", 6 * 1024 * 1024, 63 * 1024 * 1024, 2_000_000, 4_000_000)],
            Connection(path, "browser.exe", 42, "127.0.0.1:5000"));
        await monitor.PollAsync();

        Assert.Same(group, Assert.Single(page.Groups));
        Assert.True(group.IsExpanded);
        Assert.Contains("6.00 MB", group.TrafficText);
        Assert.Contains("MB/s", group.RateText);

        page.Dispose();
        monitor.Dispose();
    }

    [Fact]
    public async Task Network_dashboard_refreshes_only_the_selected_tab_and_none_in_simple_mode()
    {
        var timers = new FakeTimerFactory();
        var source = new ScriptedSource(Snapshot([], Connection(@"C:\Apps\first.exe", "first.exe", 10, "127.0.0.1:5000")));
        var service = new RecordingService();
        using var monitor = new ConnectionMonitor(source, timers);
        using var traffic = new TrafficEngine(timers);
        using var overview = new OverviewPageViewModel(monitor, traffic, serviceClient: service, timers: timers);

        await monitor.PollAsync();
        Assert.Single(overview.ConnectionsTab.VisibleConnections);
        Assert.Empty(overview.AppsTab.Apps);
        Assert.Equal(0, service.HistoryRequests);
        var historyTimer = Assert.Single(timers.Created, timer => timer.Interval == TimeSpan.FromSeconds(10));
        Assert.False(historyTimer.IsEnabled);

        overview.SelectedMonitoringTabIndex = 1;
        Assert.Single(overview.AppsTab.Apps);
        source.Snapshot = Snapshot([], Connection(@"C:\Apps\second.exe", "second.exe", 11, "127.0.0.1:5001"));
        await monitor.PollAsync();
        Assert.Equal("second.exe", Assert.Single(overview.AppsTab.Apps).Name);
        Assert.Equal("first.exe", Assert.Single(overview.ConnectionsTab.VisibleConnections).AppDisplayName);

        overview.SelectedMonitoringTabIndex = 2;
        Assert.True(historyTimer.IsEnabled);
        Assert.Equal(1, service.HistoryRequests);

        overview.ActivateSummary();
        Assert.False(historyTimer.IsEnabled);
        overview.SelectedMonitoringTabIndex = 0;
        Assert.Equal("first.exe", Assert.Single(overview.ConnectionsTab.VisibleConnections).AppDisplayName);
        overview.Activate();
        Assert.Equal("second.exe", Assert.Single(overview.ConnectionsTab.VisibleConnections).AppDisplayName);
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
        long received,
        double sentRate = 0,
        double receivedRate = 0) => new(
        path,
        name,
        path,
        sent,
        received,
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch)
    {
        SentBytesPerSecond = sentRate,
        ReceivedBytesPerSecond = receivedRate,
    };

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
        public ConnectionSnapshot Snapshot { get; set; } = snapshot;

        public string Name => "test";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Snapshot);
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public List<IUiTimer> Created { get; } = [];

        public IUiTimer Create(TimeSpan interval)
        {
            var timer = new FakeTimer(interval);
            Created.Add(timer);
            return timer;
        }

        private sealed class FakeTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;

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

    private sealed class RecordingService : IServiceRequestClient
    {
        public int HistoryRequests { get; private set; }

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            if (command == IpcCommandTypes.HistoryQuery)
            {
                HistoryRequests++;
            }

            return Task.FromException<T>(new ServiceUnavailableException(IpcErrorCodes.ServiceUnavailable, "test"));
        }
    }
}
