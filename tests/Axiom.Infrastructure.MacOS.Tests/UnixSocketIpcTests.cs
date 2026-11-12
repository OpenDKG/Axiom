// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Unix.Ipc;
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

    [Fact]
    public async Task ReadOnlyPeerGetsUnauthorizedForWriteCommandsButMayRead()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        var policy = new PeerPolicy(OwnerUid: 1, AdminGroupMayWrite: false, _ => false);
        var transport = new UnixSocketIpcTransport(paths, uid => PeerAuthorization.Decide(uid, policy) with { Allowed = true });

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(Dispatcher(line => { lock (logs) { logs.Add(line); } }), _ => { }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var health = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token);
            var denied = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.PrivacyConfigure, cts.Token);

            Assert.True(health!.Ok);
            Assert.False(denied!.Ok);
            Assert.Equal(IpcErrorCodes.Unauthorized, denied.Error!.Code);
            Assert.Contains("only allowed for root", denied.Error.Message, StringComparison.Ordinal);
            lock (logs)
            {
                Assert.Contains(logs, line => line.Contains("Denied 'privacy.configure' for uid:", StringComparison.Ordinal));
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    /// <summary>
    /// P0 #1 (GitHub review 2026-11-12): a second standard user on the same Mac. The transport
    /// identifies the peer; here the policy sees it as uid 502 while the install record names 501.
    /// Over the real socket it must get public health only, with every private read and every
    /// write refused as <c>unauthorized</c> before any handler runs.
    /// </summary>
    [Fact]
    public async Task SecondStandardUserGetsPublicHealthOnlyOverTheSocket()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        var policy = new PeerPolicy(OwnerUid: 501, AdminGroupMayWrite: true, _ => false);
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(502, policy));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(PrivateDispatcher(line => { lock (logs) { logs.Add(line); } }), line => { lock (logs) { logs.Add(line); } }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var health = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token);
            Assert.True(health!.Ok);
            var redacted = health.Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options)!;
            Assert.Equal("Running", redacted.Status);
            Assert.Equal(0, redacted.ConnectionCount);
            Assert.Null(redacted.LastError);
            Assert.Equal([IpcCommandAccess.HealthRedactedNote], redacted.Limitations);
            Assert.DoesNotContain("secret", health.Result.Value.GetRawText(), StringComparison.OrdinalIgnoreCase);

            var capabilities = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.Capabilities, cts.Token);
            Assert.True(capabilities!.Ok);

            string[] privateReads =
            [
                IpcCommandTypes.Snapshot, IpcCommandTypes.HistoryQuery, IpcCommandTypes.LiveEvents,
                IpcCommandTypes.DiagnosticsExport, IpcCommandTypes.PrivacyStatus, IpcCommandTypes.ThreatShareStatus,
                IpcCommandTypes.RulesQuery, IpcCommandTypes.ProtectionStatus,
            ];
            foreach (var command in privateReads)
            {
                var denied = await RequestAsync(paths.IpcSocketPath, command, cts.Token);
                Assert.False(denied!.Ok, command);
                Assert.Equal(IpcErrorCodes.Unauthorized, denied.Error!.Code);
                Assert.Contains("discloses machine-wide activity", denied.Error.Message, StringComparison.Ordinal);
                Assert.Contains("uid 502 may only read public service health", denied.Error.Message, StringComparison.Ordinal);
            }

            foreach (var command in new[] { IpcCommandTypes.PrivacyConfigure, IpcCommandTypes.RuleApply, IpcCommandTypes.ProtectionEnable, "something.new" })
            {
                var denied = await RequestAsync(paths.IpcSocketPath, command, cts.Token);
                Assert.False(denied!.Ok, command);
                Assert.Equal(IpcErrorCodes.Unauthorized, denied.Error!.Code);
                Assert.Contains("changes machine-wide settings", denied.Error.Message, StringComparison.Ordinal);
            }

            lock (logs)
            {
                Assert.Contains(logs, line => line.Contains("Denied 'history.query' for uid:502: private read", StringComparison.Ordinal));
                Assert.Contains(logs, line => line.Contains("Denied 'rule.apply' for uid:502: write", StringComparison.Ordinal));
                Assert.Contains(logs, line => line.Contains("uid:502 connected with public health access only", StringComparison.Ordinal));
                Assert.DoesNotContain(logs, line => line.Contains("handler reached", StringComparison.Ordinal));
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    /// <summary>The installing user keeps full access over the same transport and dispatcher.</summary>
    [Fact]
    public async Task InstallingUserReadsPrivateDataOverTheSocket()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var policy = new PeerPolicy(OwnerUid: 501, AdminGroupMayWrite: true, _ => false);
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(501, policy));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(PrivateDispatcher(_ => { }), _ => { }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var health = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token);
            Assert.True(health!.Ok);
            Assert.Equal("secret-last-error", health.Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options)!.LastError);

            // Private reads pass the authorization layer and reach the handlers (which answer with
            // their own, non-authorization errors here).
            var snapshot = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.Snapshot, cts.Token);
            Assert.Equal(IpcErrorCodes.ServiceUnavailable, snapshot!.Error!.Code);
            var history = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.HistoryQuery, cts.Token);
            Assert.Equal(IpcErrorCodes.InvalidRequest, history!.Error!.Code);
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    /// <summary>Unknown peer credentials never reach the dispatcher, regardless of policy.</summary>
    [Fact]
    public async Task UnknownPeerCredentialsAreClosedWithoutReply()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        var policy = new PeerPolicy(OwnerUid: 501, AdminGroupMayWrite: true, _ => true);
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(null, policy));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(PrivateDispatcher(_ => { }), line => { lock (logs) { logs.Add(line); } }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);
            Assert.Null(await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token));
            lock (logs)
            {
                Assert.Contains(logs, line => line.Contains("Rejected IPC client uid:unknown", StringComparison.Ordinal));
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    private static IpcRequestDispatcher PrivateDispatcher(Action<string> log) => new(
        new IpcRequestHandlers
        {
            SnapshotProvider = () => (ConnectionSnapshot?)null,
            HealthProvider = () => new ServiceHealth
            {
                Status = "Running",
                UptimeSeconds = 1,
                SourceName = "test",
                PollIntervalSeconds = 2,
                ConnectionCount = 5,
                ProcessCount = 3,
                Limitations = ["secret limitation /Applications/Secret.app"],
                LastError = "secret-last-error",
            },
            HistoryQuery = (_, _) => throw new InvalidOperationException("history handler reached"),
            PrivacyConfigure = (_, _) => throw new InvalidOperationException("write handler reached"),
        },
        writeGateOpen: () => true,
        log: log);

    [Fact]
    public void UidCapIsFourForUsersAndUnlimitedForRoot()
    {
        Assert.True(UnixSocketIpcTransport.IsWithinUidCap(501, 3));
        Assert.False(UnixSocketIpcTransport.IsWithinUidCap(501, UnixSocketIpcTransport.MaxConnectionsPerUid));
        Assert.False(UnixSocketIpcTransport.IsWithinUidCap(null, UnixSocketIpcTransport.MaxConnectionsPerUid));
        Assert.True(UnixSocketIpcTransport.IsWithinUidCap(0, 1000));
    }

    [Fact]
    public async Task FifthIdleConnectionOfTheSameUidIsRefusedAndTheSlotComesBackOnClose()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        // The test runs as one non-root uid; pretend it is uid 501 so root's exemption does not apply.
        var transport = new UnixSocketIpcTransport(paths, _ => new PeerDecision(true, "uid:501", "test"));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(Dispatcher(_ => { }), line => { lock (logs) { logs.Add(line); } }, cts.Token);
        var idle = new List<Socket>();
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);
            for (var index = 0; index < UnixSocketIpcTransport.MaxConnectionsPerUid; index++)
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(paths.IpcSocketPath), cts.Token);
                idle.Add(socket);
            }

            // Fifth: accepted by the kernel, then closed by the daemon without a reply.
            Assert.Null(await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token));
            lock (logs)
            {
                Assert.Contains(logs, line => line.Contains("more than 4 concurrent connections", StringComparison.Ordinal));
            }

            // Closing one idle connection frees its slot.
            idle[0].Dispose();
            idle.RemoveAt(0);
            IpcResponse? response = null;
            for (var attempt = 0; attempt < 50 && response is null; attempt++)
            {
                await Task.Delay(20, cts.Token);
                response = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token);
            }

            Assert.NotNull(response);
            Assert.True(response.Ok);
        }
        finally
        {
            foreach (var socket in idle)
            {
                socket.Dispose();
            }

            await cts.CancelAsync();
            await server;
        }
    }

    private static IpcRequestDispatcher Dispatcher(Action<string> log) => new(
        new IpcRequestHandlers
        {
            SnapshotProvider = () => (ConnectionSnapshot?)null,
            HealthProvider = () => new ServiceHealth
            {
                Status = "Running",
                UptimeSeconds = 1,
                SourceName = "test",
                PollIntervalSeconds = 2,
                ConnectionCount = 0,
                ProcessCount = 0,
            },
            // Must never run for a read-only caller: the dispatcher denies the command first.
            PrivacyConfigure = (_, _) => throw new InvalidOperationException("write handler reached"),
        },
        writeGateOpen: () => true,
        log: log);

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
