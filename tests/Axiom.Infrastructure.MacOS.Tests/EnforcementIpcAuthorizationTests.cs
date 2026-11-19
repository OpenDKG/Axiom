// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// Cross-user authorization of <c>enforcement.status</c>, <c>enforcement.evaluate</c> and
/// <c>enforcement.receipts</c> (upstream #322) on the Unix socket: decisions, receipts, indicator
/// references, paths and agent identities are owner-only; nothing of them is public health data.
/// </summary>
public sealed class EnforcementIpcAuthorizationTests
{
    private const string SecretTarget = "/Users/owner/.ssh/id_rsa-secret-target";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static readonly PeerPolicy OwnerOnly = new(OwnerUid: 501, AdminGroupMayWrite: true, _ => false);

    /// <summary>Per command: root and the install owner are permitted, any other uid is not.</summary>
    [Theory]
    [InlineData("enforcement.status", 0u, true)]
    [InlineData("enforcement.status", 501u, true)]
    [InlineData("enforcement.status", 502u, false)]
    [InlineData("enforcement.receipts", 0u, true)]
    [InlineData("enforcement.receipts", 501u, true)]
    [InlineData("enforcement.receipts", 502u, false)]
    [InlineData("enforcement.evaluate", 0u, true)]
    [InlineData("enforcement.evaluate", 501u, true)]
    [InlineData("enforcement.evaluate", 502u, false)]
    public void DecidePerCommand(string command, uint uid, bool permitted)
    {
        var decision = PeerAuthorization.Decide(uid, OwnerOnly);

        Assert.True(decision.Allowed);
        Assert.NotEqual(IpcCommandClass.PublicRead, IpcCommandAccess.Classify(command));
        Assert.Equal(permitted, decision.ToCaller().Permits(IpcCommandAccess.Classify(command)));
        Assert.Equal(permitted, PeerAuthorization.Permits(uid, OwnerOnly, IpcCommandAccess.Classify(command)));
    }

    /// <summary>Without an install record only root may use them.</summary>
    [Theory]
    [InlineData("enforcement.status")]
    [InlineData("enforcement.receipts")]
    [InlineData("enforcement.evaluate")]
    public void WithoutAnInstallOwnerOnlyRootIsPermitted(string command)
    {
        var commandClass = IpcCommandAccess.Classify(command);

        Assert.True(PeerAuthorization.Decide(0).ToCaller().Permits(commandClass));
        Assert.False(PeerAuthorization.Decide(501).ToCaller().Permits(commandClass));
    }

    /// <summary>A second local user gets <c>unauthorized</c> for all three and no handler runs.</summary>
    [Fact]
    public async Task SecondUserGetsUnauthorizedForEnforcementCommandsOverTheSocket()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        var probe = new Probe();
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(502, OwnerOnly));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(probe.Dispatcher(line => { lock (logs) { logs.Add(line); } }), line => { lock (logs) { logs.Add(line); } }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            // The public tier still answers, and says nothing about enforcement.
            var health = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, null, cts.Token);
            Assert.True(health!.Ok);
            Assert.DoesNotContain("enforcement", health.Result!.Value.GetRawText(), StringComparison.OrdinalIgnoreCase);

            foreach (var command in new[] { IpcCommandTypes.EnforcementStatus, IpcCommandTypes.EnforcementReceipts })
            {
                var denied = await RequestAsync(paths.IpcSocketPath, command, null, cts.Token);
                Assert.False(denied!.Ok, command);
                Assert.Equal(IpcErrorCodes.Unauthorized, denied.Error!.Code);
                Assert.Contains("discloses machine-wide activity", denied.Error.Message, StringComparison.Ordinal);
                Assert.Contains("uid 502 may only read public service health", denied.Error.Message, StringComparison.Ordinal);
                Assert.Null(denied.Result);
            }

            var evaluate = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.EnforcementEvaluate, EvaluatePayload(), cts.Token);
            Assert.False(evaluate!.Ok);
            Assert.Equal(IpcErrorCodes.Unauthorized, evaluate.Error!.Code);
            Assert.Contains("changes machine-wide settings", evaluate.Error.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(SecretTarget, evaluate.Error.Message, StringComparison.Ordinal);

            Assert.Equal(0, probe.Calls);
            lock (logs)
            {
                Assert.Contains(logs, line => line.Contains("Denied 'enforcement.status' for uid:502: private read", StringComparison.Ordinal));
                Assert.Contains(logs, line => line.Contains("Denied 'enforcement.receipts' for uid:502: private read", StringComparison.Ordinal));
                Assert.Contains(logs, line => line.Contains("Denied 'enforcement.evaluate' for uid:502: write", StringComparison.Ordinal));
                Assert.DoesNotContain(logs, line => line.Contains(SecretTarget, StringComparison.Ordinal));
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    /// <summary>The install owner and root reach the handlers over the same socket; evaluate gets the peer actor.</summary>
    [Theory]
    [InlineData(501u, "uid:501")]
    [InlineData(0u, "uid:0")]
    public async Task OwnerAndRootReachTheEnforcementHandlersOverTheSocket(uint uid, string actor)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var probe = new Probe();
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(uid, OwnerOnly));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(probe.Dispatcher(_ => { }), _ => { }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var status = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.EnforcementStatus, null, cts.Token);
            Assert.True(status!.Ok);
            Assert.Equal("rev-7", status.Result!.Value.Deserialize<EnforcementStatusDto>(IpcJson.Options)!.Revision);

            var receipts = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.EnforcementReceipts, null, cts.Token);
            Assert.True(receipts!.Ok);

            var verdict = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.EnforcementEvaluate, EvaluatePayload(), cts.Token);
            Assert.True(verdict!.Ok);
            Assert.Equal(actor, probe.LastActor);
            Assert.Equal(3, probe.Calls);
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    /// <summary>The daemon wiring (no enforcement handlers): the owner gets upstream's not_supported, a second user still unauthorized.</summary>
    [Theory]
    [InlineData(501u, IpcErrorCodes.NotSupported)]
    [InlineData(502u, IpcErrorCodes.Unauthorized)]
    public async Task DaemonWithoutEnforcementAnswersNotSupportedOnlyToAuthorizedCallers(uint uid, string expectedCode)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var dispatcher = new IpcRequestDispatcher(
            new IpcRequestHandlers
            {
                SnapshotProvider = () => (ConnectionSnapshot?)null,
                HealthProvider = Health,
            },
            writeGateOpen: () => true);
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(uid, OwnerOnly));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(dispatcher, _ => { }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            foreach (var command in new[] { IpcCommandTypes.EnforcementStatus, IpcCommandTypes.EnforcementReceipts, IpcCommandTypes.EnforcementEvaluate })
            {
                var reply = await RequestAsync(paths.IpcSocketPath, command, command == IpcCommandTypes.EnforcementEvaluate ? EvaluatePayload() : null, cts.Token);
                Assert.False(reply!.Ok, command);
                Assert.Equal(expectedCode, reply.Error!.Code);
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    private static ServiceHealth Health() => new()
    {
        Status = "Running",
        UptimeSeconds = 1,
        SourceName = "test",
        PollIntervalSeconds = 2,
        ConnectionCount = 0,
        ProcessCount = 0,
    };

    private static EnforcementEvaluateRequest EvaluatePayload() => new()
    {
        RequestId = "req-1",
        AgentId = "opencode",
        Kind = "readFile",
        Target = SecretTarget,
    };

    private static async Task<IpcResponse?> RequestAsync(string path, string command, object? payload, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        var envelope = new IpcEnvelope
        {
            Type = command,
            Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, IpcJson.Options),
        };
        await IpcLineProtocol.WriteLineAsync(stream, JsonSerializer.Serialize(envelope, IpcJson.Options), cancellationToken);
        var line = await new IpcLineReader(stream).ReadLineAsync(IpcProtocol.MaxResponseBytes, cancellationToken);
        return line is null ? null : JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options);
    }

    private static async Task WaitForSocketAsync(string path, CancellationToken cancellationToken)
    {
        while (!File.Exists(path))
        {
            await Task.Delay(20, cancellationToken);
        }

        await Task.Delay(50, cancellationToken);
    }

    private sealed class Probe
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public string? LastActor { get; private set; }

        public IpcRequestDispatcher Dispatcher(Action<string> log) => new(
            new IpcRequestHandlers
            {
                SnapshotProvider = () => (ConnectionSnapshot?)null,
                HealthProvider = Health,
                EnforcementStatus = _ =>
                {
                    Interlocked.Increment(ref _calls);
                    return Task.FromResult(new EnforcementStatusDto
                    {
                        Enabled = true,
                        Revision = "rev-7",
                        AgentCount = 1,
                        RuleCount = 2,
                        ProtectedResourceCount = 3,
                        Error = "Access to the path '/Users/owner/Library/secret-policy.json' is denied.",
                    });
                },
                EnforcementReceipts = _ =>
                {
                    Interlocked.Increment(ref _calls);
                    return Task.FromResult(new EnforcementReceiptsSnapshotDto { ChainValid = true, Total = 0, Receipts = [] });
                },
                EnforcementEvaluate = (request, actor, _) =>
                {
                    Interlocked.Increment(ref _calls);
                    LastActor = actor;
                    return Task.FromResult(new EnforcementVerdictDto
                    {
                        RequestId = request.RequestId,
                        Decision = "block",
                        RuleId = "rule-1",
                        ReasonCode = "test",
                        AvailableStrength = "observation",
                        EvaluatedUtc = DateTimeOffset.UnixEpoch,
                    });
                },
            },
            writeGateOpen: () => true,
            log: log);
    }
}
