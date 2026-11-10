// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.MacOS.Ipc;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// End-to-end over a real Unix domain socket: the transport reads the peer uid (getpeereid on
/// macOS, SO_PEERCRED on Linux), authorizes it and serves the shared dispatcher.
/// </summary>
public sealed class UnixSocketIpcTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static IpcRequestDispatcher Dispatcher() => new(
        new IpcRequestHandlers
        {
            SnapshotProvider = () => (ConnectionSnapshot?)null,
            HealthProvider = () => new ServiceHealth
            {
                Status = "Running",
                UptimeSeconds = 42,
                SourceName = "test",
                PollIntervalSeconds = 2,
                ConnectionCount = 3,
                ProcessCount = 1,
            },
        },
        writeGateOpen: () => false);

    [Fact]
    public async Task ServiceHealthRoundTripsWithPeerUid()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        uint? seenUid = null;
        string? seenActor = null;
        var transport = new UnixSocketIpcTransport(paths, uid =>
        {
            seenUid = uid;
            var decision = PeerAuthorization.Decide(uid);
            seenActor = decision.Actor;
            return decision with { Allowed = true };
        });

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(Dispatcher(), _ => { }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var mode = File.GetUnixFileMode(paths.IpcSocketPath);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead |
                UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite, mode);

            var response = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token);

            Assert.NotNull(response);
            Assert.True(response.Ok);
            var health = response.Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options)!;
            Assert.Equal("Running", health.Status);
            Assert.Equal(42, health.UptimeSeconds);
            Assert.Equal(geteuid(), seenUid);
            Assert.Equal("uid:" + geteuid(), seenActor);
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }

        Assert.False(File.Exists(paths.IpcSocketPath));
    }

    [Fact]
    public async Task PipeClientConnectsToSocketPath()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var transport = new UnixSocketIpcTransport(paths, uid => new PeerDecision(true, "uid:" + uid, "test"));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(Dispatcher(), _ => { }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var client = new IpcPipeClient(paths.IpcSocketPath, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
            var capabilities = await client.SendAsync<ServiceCapabilities>(IpcCommandTypes.Capabilities, null, cts.Token);

            Assert.Contains(IpcCommandTypes.ServiceHealth, capabilities.Commands);
            Assert.False(capabilities.FirewallWrites);
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    [Fact]
    public async Task RejectedPeerIsDisconnectedWithoutReply()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        var transport = new UnixSocketIpcTransport(paths, uid => new PeerDecision(false, "uid:" + uid, "denied by test"));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(Dispatcher(), line => { lock (logs) { logs.Add(line); } }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var response = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token);

            Assert.Null(response);
            lock (logs)
            {
                Assert.Contains(logs, line => line.Contains("denied by test", StringComparison.Ordinal));
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    private static async Task<IpcResponse?> RequestAsync(string path, string command, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        var envelope = new IpcEnvelope { Type = command };
        try
        {
            await IpcLineProtocol.WriteLineAsync(stream, JsonSerializer.Serialize(envelope, IpcJson.Options), cancellationToken);
            var line = await new IpcLineReader(stream).ReadLineAsync(IpcProtocol.MaxResponseBytes, cancellationToken);
            return line is null ? null : JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options);
        }
        catch (IOException)
        {
            // The server closed the connection (rejected peer).
            return null;
        }
    }

    private static async Task WaitForSocketAsync(string path, CancellationToken cancellationToken)
    {
        while (!File.Exists(path))
        {
            await Task.Delay(20, cancellationToken);
        }

        // The mode is applied right after bind; give the listener a moment to reach listen().
        await Task.Delay(50, cancellationToken);
    }

    [DllImport("libc")]
    private static extern uint geteuid();
}
