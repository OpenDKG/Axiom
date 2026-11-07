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
        var monitor = new ConnectionMonitor(source, new FakeTimerFactory());

        await monitor.PollAsync();
        await monitor.PollAsync();

        Assert.Single(monitor.Connections);
        Assert.Equal(1, monitor.ProcessCount);
        Assert.Equal("observed", monitor.Connections[0].QualityText);
    }

    [Fact]
    public void Byte_formatter_does_not_invent_a_rate()
    {
        Assert.Equal("—", ByteFormatter.Rate(double.NaN));
        Assert.Equal("1.0 KB/s", ByteFormatter.Rate(1024));
        Assert.Equal("—", ByteFormatter.Rate(-1));
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

    private sealed class FakeSource : IConnectionSnapshotSource
    {
        public string Name => "test source";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Snapshot(Connection("app.exe", 42, "127.0.0.1:1", "1.1.1.1:2")));
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
