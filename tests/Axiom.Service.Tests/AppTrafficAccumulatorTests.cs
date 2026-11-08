// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class AppTrafficAccumulatorTests
{
    [Fact]
    public void First_poll_counts_the_connection_total()
    {
        var accumulator = new AppTrafficAccumulator();
        var now = DateTimeOffset.UnixEpoch;

        var snapshot = accumulator.Apply(
            Snapshot(Connection(@"C:\Apps\browser.exe", 42, 1_000, 2_000)),
            now);

        var app = Assert.Single(snapshot.AppTraffic);
        Assert.Equal(@"C:\Apps\browser.exe", app.Key);
        Assert.Equal(1_000, app.BytesSent);
        Assert.Equal(2_000, app.BytesReceived);
        Assert.Equal(now, app.SinceUtc);
    }

    [Fact]
    public void Later_polls_add_only_the_delta()
    {
        var accumulator = new AppTrafficAccumulator();
        var now = DateTimeOffset.UnixEpoch;

        accumulator.Apply(Snapshot(Connection(@"C:\Apps\browser.exe", 42, 1_000, 2_000)), now);
        var snapshot = accumulator.Apply(
            Snapshot(Connection(@"C:\Apps\browser.exe", 42, 1_400, 2_500)),
            now.AddSeconds(1));

        var app = Assert.Single(snapshot.AppTraffic);
        Assert.Equal(1_400, app.BytesSent);
        Assert.Equal(2_500, app.BytesReceived);
    }

    [Fact]
    public void Two_sockets_of_the_same_app_are_summed()
    {
        var accumulator = new AppTrafficAccumulator();
        var snapshot = accumulator.Apply(
            Snapshot(
                Connection(@"C:\Apps\browser.exe", 42, 100, 200, "127.0.0.1:5000", "1.1.1.1:443"),
                Connection(@"C:\Apps\browser.exe", 43, 300, 400, "127.0.0.1:5001", "1.1.1.1:443")),
            DateTimeOffset.UnixEpoch);

        var app = Assert.Single(snapshot.AppTraffic);
        Assert.Equal(400, app.BytesSent);
        Assert.Equal(600, app.BytesReceived);
    }

    [Fact]
    public void Totals_survive_when_the_connection_closes()
    {
        var accumulator = new AppTrafficAccumulator();
        var now = DateTimeOffset.UnixEpoch;

        accumulator.Apply(Snapshot(Connection(@"C:\Apps\browser.exe", 42, 1_000, 2_000)), now);
        var closed = accumulator.Apply(Snapshot(), now.AddSeconds(1));
        var reopened = accumulator.Apply(
            Snapshot(Connection(@"C:\Apps\browser.exe", 42, 50, 60)),
            now.AddSeconds(2));

        Assert.Equal(1_000, Assert.Single(closed.AppTraffic).BytesSent);
        var app = Assert.Single(reopened.AppTraffic);
        Assert.Equal(1_050, app.BytesSent);
        Assert.Equal(2_060, app.BytesReceived);
    }

    [Fact]
    public void A_lower_counter_is_treated_as_a_new_connection()
    {
        var accumulator = new AppTrafficAccumulator();
        var now = DateTimeOffset.UnixEpoch;

        accumulator.Apply(Snapshot(Connection(@"C:\Apps\browser.exe", 42, 500, 500)), now);
        var snapshot = accumulator.Apply(
            Snapshot(Connection(@"C:\Apps\browser.exe", 42, 40, 60)),
            now.AddSeconds(1));

        var app = Assert.Single(snapshot.AppTraffic);
        Assert.Equal(540, app.BytesSent);
        Assert.Equal(560, app.BytesReceived);
    }

    [Fact]
    public void Rows_without_measured_bytes_are_ignored()
    {
        var accumulator = new AppTrafficAccumulator();
        var snapshot = accumulator.Apply(
            Snapshot(Connection(@"C:\Apps\udp.exe", 42, null, null)),
            DateTimeOffset.UnixEpoch);

        Assert.Empty(snapshot.AppTraffic);
    }

    [Fact]
    public void Rates_reflect_the_latest_poll_interval()
    {
        var accumulator = new AppTrafficAccumulator();
        var now = DateTimeOffset.UnixEpoch;

        accumulator.Apply(Snapshot(Connection(@"C:\Apps\browser.exe", 42, 1_000, 2_000)), now);
        var snapshot = accumulator.Apply(
            Snapshot(Connection(@"C:\Apps\browser.exe", 42, 3_000, 6_000)),
            now.AddSeconds(2));

        var app = Assert.Single(snapshot.AppTraffic);
        Assert.Equal(1_000, app.SentBytesPerSecond, 3);
        Assert.Equal(2_000, app.ReceivedBytesPerSecond, 3);

        var idle = accumulator.Apply(
            Snapshot(Connection(@"C:\Apps\browser.exe", 42, 3_000, 6_000)),
            now.AddSeconds(3));

        Assert.Equal(0, Assert.Single(idle.AppTraffic).SentBytesPerSecond, 3);
        Assert.Equal(0, Assert.Single(idle.AppTraffic).ReceivedBytesPerSecond, 3);
    }

    private static ConnectionSnapshot Snapshot(params LiveConnection[] connections) => new()
    {
        CapturedUtc = DateTimeOffset.UnixEpoch,
        Connections = connections,
        ProcessCount = connections.Select(connection => connection.ProcessId).Distinct().Count(),
        SourceName = "test",
    };

    private static LiveConnection Connection(
        string path,
        int processId,
        long? sent,
        long? received,
        string local = "127.0.0.1:50000",
        string remote = "1.1.1.1:443") => new()
    {
        AppDisplayName = System.IO.Path.GetFileName(path),
        AppPath = path,
        ProcessId = processId,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = local,
        RemoteEndpoint = remote,
        State = "Established",
        Direction = ConnectionDirection.Outbound,
        InterfaceName = string.Empty,
        FirstObservedUtc = DateTimeOffset.UnixEpoch,
        ObservedBytesSent = sent,
        ObservedBytesReceived = received,
    };
}
