// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class PortablePresentationTests
{
    [Fact]
    public async Task Connection_monitor_keeps_one_row_for_the_same_socket()
    {
        var source = new FakeSource();
        using var monitor = new ConnectionMonitor(source, new FakeTimerFactory());

        await monitor.PollAsync();
        await monitor.PollAsync();

        Assert.Single(monitor.Connections);
        Assert.Equal(1, monitor.ProcessCount);
        Assert.Equal("observed", monitor.Connections[0].QualityText);
    }

    [Fact]
    public async Task Connection_monitor_publishes_recovery_with_the_first_successful_poll()
    {
        var timeout = true;
        var source = new CallbackSource(() => timeout
            ? Task.FromException<ConnectionSnapshot>(new TaskCanceledException("Snapshot timed out."))
            : Task.FromResult(Snapshot(Connection("app.exe", 42, "127.0.0.1:1", "1.1.1.1:2"))));
        using var monitor = new ConnectionMonitor(source, new FakeTimerFactory());
        var updates = new List<(string? Error, int Sockets)>();
        monitor.Updated += (_, _) => updates.Add((monitor.LastError, monitor.Connections.Count));

        await monitor.PollAsync();
        timeout = false;
        await monitor.PollAsync();

        Assert.Equal<(string?, int)>([("Snapshot timed out.", 0), (null, 1)], updates);
    }

    [Fact]
    public async Task Connection_monitor_ignores_a_snapshot_that_finishes_after_disposal()
    {
        var pending = new TaskCompletionSource<ConnectionSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        var captures = 0;
        var monitor = new ConnectionMonitor(new CallbackSource(() =>
        {
            captures++;
            return pending.Task;
        }), new FakeTimerFactory());
        var notifications = 0;
        monitor.Updated += (_, _) => notifications++;

        var poll = monitor.PollAsync();
        monitor.Dispose();
        pending.SetResult(Snapshot(Connection("app.exe", 42, "127.0.0.1:1", "1.1.1.1:2")));
        await poll;
        await monitor.PollAsync();

        Assert.Equal(1, captures);
        Assert.Equal(0, notifications);
        Assert.Empty(monitor.Connections);
    }

    [Fact]
    public void Connection_row_reuses_search_text_for_traffic_updates_and_skips_unchanged_rows()
    {
        var source = Connection("app.exe", 42, "127.0.0.1:1", "1.1.1.1:2");
        var row = new ConnectionRow(source);
        var searchText = row.SearchBlob;
        var updates = 0;
        row.PropertyChanged += (_, _) => updates++;

        row.Update(source with { });
        Assert.Equal(0, updates);

        row.Update(source with { ObservedBytesSent = 1024 });
        Assert.Equal(1, updates);
        Assert.Equal(1024, row.ObservedBytesSent);
        Assert.Same(searchText, row.SearchBlob);

        row.Update(source with { AppDisplayName = "renamed.exe" });
        Assert.Equal(2, updates);
        Assert.Contains("renamed.exe", row.SearchBlob, StringComparison.Ordinal);
    }

    [Fact]
    public void Byte_formatter_does_not_invent_a_rate()
    {
        Assert.Equal("—", ByteFormatter.Rate(double.NaN));
        Assert.Equal("1.0 KB/s", ByteFormatter.Rate(1024));
        Assert.Equal("—", ByteFormatter.Rate(-1));
    }

    [Fact]
    public void Byte_formatter_reports_megabytes_for_app_totals()
    {
        Assert.Equal("0.00 MB", ByteFormatter.Megabytes(0));
        Assert.Equal("1.00 MB", ByteFormatter.Megabytes(1024 * 1024));
        Assert.Equal("1.50 MB", ByteFormatter.Megabytes(1024 * 1024 * 3 / 2));
    }

    [Fact]
    public void App_grouping_skips_unowned_pid_zero_rows()
    {
        var snapshot = Snapshot(
            Connection("app.exe", 0, "127.0.0.1:1", "1.1.1.1:2"),
            Connection("app.exe", 42, "127.0.0.1:1", "1.1.1.1:2"));
        var rows = snapshot.Connections.Select(connection => new ConnectionRow(connection)).ToList();

        var groups = AppGrouping.Group(rows);

        Assert.Single(groups);
        Assert.Equal(1, groups[0].SocketCount);
        Assert.Equal(1, AppGrouping.CountUnowned(rows));
    }

    [Fact]
    public async Task Service_probe_reports_offline_without_inventing_health()
    {
        var probe = new ServiceStatusProbe(new OfflineServiceClient());

        var status = await probe.ProbeAsync(CancellationToken.None);

        Assert.False(status.IsConnected);
        Assert.Null(status.Health);
        Assert.Null(status.Capabilities);
        Assert.Contains("offline", status.LastError, StringComparison.OrdinalIgnoreCase);
        Assert.False(status.ServiceResponded);
    }

    [Fact]
    public async Task Service_probe_tells_an_error_the_service_answered_from_an_unreachable_service()
    {
        var probe = new ServiceStatusProbe(new ErrorAnsweringServiceClient());

        var status = await probe.ProbeAsync(CancellationToken.None);

        // Not connected for the probe's purpose (no capabilities), but the service was reached.
        Assert.False(status.IsConnected);
        Assert.Null(status.Capabilities);
        Assert.True(status.ServiceResponded);
    }

    [Fact]
    public async Task Service_probe_exposes_the_real_capabilities_and_health()
    {
        var probe = new ServiceStatusProbe(new OnlineServiceClient());

        var status = await probe.ProbeAsync(CancellationToken.None);

        Assert.True(status.IsConnected);
        Assert.Equal(IpcProtocol.CurrentVersion, status.Capabilities?.ProtocolVersion);
        Assert.False(status.Capabilities?.FirewallWrites);
        Assert.Equal(7, status.Health?.ConnectionCount);
    }

    [Fact]
    public async Task Service_snapshot_source_uses_the_snapshot_command_only()
    {
        var client = new OnlineServiceClient();
        var source = new ServiceSnapshotSource(client);

        await source.CaptureAsync(CancellationToken.None);

        Assert.Single(client.Commands);
        Assert.Equal(IpcCommandTypes.Snapshot, client.Commands[0]);
    }

    private static LiveConnection Connection(string app, int pid, string local, string remote) => new()
    {
        AppDisplayName = app,
        AppPath = @"C:\apps\" + app,
        ProcessId = pid,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = local,
        RemoteEndpoint = remote,
        State = "Established",
        Direction = ConnectionDirection.Outbound,
        InterfaceName = string.Empty,
        FirstObservedUtc = DateTimeOffset.UtcNow,
        IsNew = true,
    };

    private static ConnectionSnapshot Snapshot(params LiveConnection[] connections) => new()
    {
        CapturedUtc = DateTimeOffset.UtcNow,
        Connections = connections,
        ProcessCount = connections.Select(connection => connection.ProcessId).Distinct().Count(),
        SourceName = "test source",
    };

    [Fact]
    public void Traffic_range_switch_clears_the_live_series_and_accepts_persisted_history()
    {
        using var traffic = new TrafficEngine(new FakeTimerFactory());
        traffic.Start();
        var liveCount = traffic.UploadSeries.Count;
        Assert.True(liveCount > 1);
        Assert.True(traffic.IsLive);

        traffic.SetRange(TrafficRange.LastHour);

        Assert.False(traffic.IsLive);
        Assert.Empty(traffic.UploadSeries);
        Assert.Empty(traffic.DownloadSeries);
        Assert.False(traffic.HasHistoryData);
        Assert.Contains("1 min", traffic.BucketLabel, StringComparison.Ordinal);

        traffic.SetHistory(
            TrafficRange.LastHour,
            60,
            [1_024d, double.NaN, 2_048d],
            [4_096d, double.NaN, 8_192d],
            "service history");

        Assert.Equal(3, traffic.UploadSeries.Count);
        Assert.True(traffic.HasHistoryData);
        Assert.Equal("service history", traffic.RangeNote);
        Assert.Equal(TrafficRange.LastHour, traffic.Range);

        // History for a range that is no longer selected must not replace the visible series.
        traffic.SetRange(TrafficRange.LastDay);
        traffic.SetHistory(TrafficRange.LastHour, 60, [9d], [9d], "stale");
        Assert.Empty(traffic.UploadSeries);

        traffic.SetRange(TrafficRange.LastFiveMinutes);

        Assert.True(traffic.IsLive);
        Assert.Equal(liveCount, traffic.UploadSeries.Count);
        Assert.Equal(liveCount, traffic.DownloadSeries.Count);
        Assert.False(traffic.HasHistoryData);
    }

    private sealed class FakeSource : IConnectionSnapshotSource
    {
        public string Name => "test source";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Snapshot(Connection("app.exe", 42, "127.0.0.1:1", "1.1.1.1:2")));
    }

    private sealed class CallbackSource(Func<Task<ConnectionSnapshot>> capture) : IConnectionSnapshotSource
    {
        public string Name => "test source";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) => capture();
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new FakeTimer(interval);

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

            public void Dispose()
            {
            }
        }
    }

    private sealed class OfflineServiceClient : IServiceRequestClient
    {
        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken) =>
            throw new ServiceUnavailableException(
                IpcErrorCodes.ServiceUnavailable,
                "The local service is offline.");
    }

    private sealed class ErrorAnsweringServiceClient : IServiceRequestClient
    {
        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken) =>
            throw new ServiceUnavailableException(IpcErrorCodes.NotSupported, "not supported");
    }

    private sealed class OnlineServiceClient : IServiceRequestClient
    {
        public List<string> Commands { get; } = [];

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            Commands.Add(command);
            object result = command switch
            {
                IpcCommandTypes.Capabilities => new ServiceCapabilities
                {
                    ProtocolVersion = IpcProtocol.CurrentVersion,
                    Commands = [IpcCommandTypes.Snapshot],
                    Monitoring = true,
                    FirewallWrites = false,
                    Milestone = "test",
                },
                IpcCommandTypes.ServiceHealth => new ServiceHealth
                {
                    Status = "running",
                    UptimeSeconds = 5,
                    SourceName = "test",
                    PollIntervalSeconds = 1,
                    ConnectionCount = 7,
                    ProcessCount = 3,
                },
                IpcCommandTypes.Snapshot => Snapshot(Connection("app.exe", 42, "127.0.0.1:1", "1.1.1.1:2")),
                _ => throw new InvalidOperationException($"Unexpected command {command}"),
            };

            return Task.FromResult((T)result);
        }
    }
}
