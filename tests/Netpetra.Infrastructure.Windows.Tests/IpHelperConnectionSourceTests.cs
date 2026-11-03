// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using Netpetra.Contracts.Monitoring;
using Netpetra.Infrastructure.Windows.IpHelper;
using Netpetra.Infrastructure.Windows.ProcessIdentity;
using Xunit;

namespace Netpetra.Infrastructure.Windows.Tests;

/// <summary>
/// Reads the real owner tables on the test host. These are read-only checks: no listener is left
/// behind and no firewall state is touched.
/// </summary>
public sealed class IpHelperConnectionSourceTests
{
    [Fact]
    public async Task Snapshot_contains_a_controlled_loopback_tcp_connection()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            using var accepted = await accept;

            var source = new IpHelperConnectionSource();
            var snapshot = await source.CaptureAsync(CancellationToken.None);

            var match = snapshot.Connections.FirstOrDefault(connection =>
                connection.ProcessId == Environment.ProcessId &&
                connection.Protocol == TransportProtocol.Tcp &&
                (connection.LocalEndpoint.EndsWith($":{port}", StringComparison.Ordinal) ||
                 connection.RemoteEndpoint.EndsWith($":{port}", StringComparison.Ordinal)));

            Assert.NotNull(match);
            Assert.True(match.IsLoopback);
            Assert.Equal(DataQuality.Observed, match.Quality);
            Assert.False(string.IsNullOrEmpty(match.AppPath));
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task Snapshot_contains_a_controlled_udp_endpoint()
    {
        using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

        var source = new IpHelperConnectionSource();
        var snapshot = await source.CaptureAsync(CancellationToken.None);

        var match = snapshot.Connections.FirstOrDefault(connection =>
            connection.Protocol == TransportProtocol.Udp &&
            connection.ProcessId == Environment.ProcessId &&
            connection.LocalEndpoint.EndsWith($":{port}", StringComparison.Ordinal));

        Assert.NotNull(match);
        Assert.Equal("—", match.RemoteEndpoint);
        Assert.Equal(ConnectionDirection.Unknown, match.Direction);
        Assert.Equal(DataQuality.Partial, match.Quality);
    }

    [Fact]
    public async Task Snapshot_reports_processes_and_quality_metadata()
    {
        var source = new IpHelperConnectionSource();

        var snapshot = await source.CaptureAsync(CancellationToken.None);

        Assert.Equal(source.Name, snapshot.SourceName);
        Assert.NotEmpty(snapshot.Connections);
        Assert.True(snapshot.ProcessCount > 0);
        Assert.NotEmpty(snapshot.Limitations);
        Assert.All(snapshot.Connections, connection =>
            Assert.False(string.IsNullOrWhiteSpace(connection.AppDisplayName)));
    }

    [Fact]
    public void Process_identity_resolves_the_test_host()
    {
        var identity = new ProcessIdentityResolver().Resolve(Environment.ProcessId);

        Assert.True(identity.IsResolved);
        Assert.True(File.Exists(identity.ExecutablePath));
        Assert.Equal(Environment.ProcessId, identity.ProcessId);
    }

    [Fact]
    public void Process_identity_marks_pid_zero_as_system()
    {
        var identity = new ProcessIdentityResolver().Resolve(0);

        Assert.False(identity.IsResolved);
        Assert.Contains("System", identity.DisplayName, StringComparison.Ordinal);
    }
}
