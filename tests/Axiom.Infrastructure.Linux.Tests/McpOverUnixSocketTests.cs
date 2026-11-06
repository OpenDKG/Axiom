// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Linux.Ipc;
using Axiom.McpServer;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// Exercises the MCP service client against the real Linux socket server and dispatcher, rather
/// than a mocked pipe. The stdio MCP host uses the same client.
/// </summary>
public sealed class McpOverUnixSocketTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-mcp-" + Guid.NewGuid().ToString("N"));

    private readonly CancellationTokenSource _cancellation = new();

    private UnixSocketServer? _server;

    private Task? _running;

    private string? _previousSocket;

    public void Dispose()
    {
        _cancellation.Cancel();
        try
        {
            _running?.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
        }

        _server?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Environment.SetEnvironmentVariable(IpcEndpoint.SocketPathVariable, _previousSocket);
        _cancellation.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task Mcp_client_reads_health_and_snapshot_over_the_real_socket()
    {
        Directory.CreateDirectory(_directory);
        var socketPath = Path.Combine(_directory, "service.sock");
        var processor = new IpcRequestProcessor(
            snapshot: () => new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections =
                [
                    new LiveConnection
                    {
                        AppDisplayName = "curl",
                        AppPath = "/usr/bin/curl",
                        ProcessId = 4242,
                        Protocol = TransportProtocol.Tcp,
                        LocalEndpoint = "127.0.0.1:40000",
                        RemoteEndpoint = "127.0.0.1:9099",
                        State = "Established",
                        Direction = ConnectionDirection.Outbound,
                        InterfaceName = string.Empty,
                        FirstObservedUtc = DateTimeOffset.UtcNow,
                    },
                ],
                ProcessCount = 1,
                SourceName = "procfs (TCP/UDP v4+v6)",
            },
            health: () => new ServiceHealth
            {
                Status = "running",
                UptimeSeconds = 3,
                SourceName = "procfs (TCP/UDP v4+v6)",
                PollIntervalSeconds = 1,
                ConnectionCount = 1,
                ProcessCount = 1,
            });

        _previousSocket = Environment.GetEnvironmentVariable(IpcEndpoint.SocketPathVariable);
        Environment.SetEnvironmentVariable(IpcEndpoint.SocketPathVariable, socketPath);

        _server = new UnixSocketServer(socketPath, PosixIdentity.EffectiveUserId, processor);
        _running = _server.RunAsync(_cancellation.Token);

        for (var attempt = 0; attempt < 100 && !File.Exists(socketPath); attempt++)
        {
            await Task.Delay(20);
        }

        var client = new AxiomServiceClient();
        var health = await client.GetHealthAsync(CancellationToken.None);
        var snapshot = await client.GetSnapshotAsync(CancellationToken.None);

        Assert.Equal("running", health.Status);
        Assert.Single(snapshot.Connections);
        Assert.Equal(4242, snapshot.Connections[0].ProcessId);
    }
}
