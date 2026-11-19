// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Unix.Ipc;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// Cross-user authorization of <c>enforcement.status</c>, <c>enforcement.evaluate</c> and
/// <c>enforcement.receipts</c> (upstream #322) on the Linux daemon socket, with the Linux account
/// range and <c>LinuxServicePaths</c>: decisions, receipts, indicator references and policy paths
/// are private to root and the install owner; none of it is public health data. The Linux daemon
/// registers no enforcement controller, so an authorized caller gets upstream's
/// <c>not_supported</c> and any other uid gets <c>unauthorized</c> before a handler could run.
/// The last test uses a real second account through <c>sudo -n -u</c> and real SO_PEERCRED; it
/// runs only when <c>AXIOM_TEST_SECOND_USER</c> names one (docs/LINUX_TEST_REPORT.md records the run).
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public sealed class LinuxEnforcementIpcAuthorizationTests
{
    private const string SecretTarget = "/home/owner/.ssh/id_ed25519-secret-target";

    private const uint Owner = 1000;

    private const uint Other = 1001;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    private static readonly PeerPolicy OwnerOnly = new(OwnerUid: Owner, AdminGroupMayWrite: true, _ => false);

    private static readonly string[] EnforcementCommands =
    [
        IpcCommandTypes.EnforcementStatus,
        IpcCommandTypes.EnforcementReceipts,
        IpcCommandTypes.EnforcementEvaluate,
    ];

    /// <summary>A second local user gets <c>unauthorized</c> for all three and no handler runs.</summary>
    [Fact]
    public async Task SecondUserGetsUnauthorizedAndNoHandlerRuns()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = LinuxServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        var probe = new Probe();
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(Other, OwnerOnly, UnixAccountRange.Linux));

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
                Assert.Contains("uid 1001 may only read public service health", denied.Error.Message, StringComparison.Ordinal);
                Assert.Null(denied.Result);
            }

            var evaluate = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.EnforcementEvaluate, EvaluatePayload(), cts.Token);
            Assert.False(evaluate!.Ok);
            Assert.Equal(IpcErrorCodes.Unauthorized, evaluate.Error!.Code);
            Assert.Contains("changes machine-wide settings", evaluate.Error.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(SecretTarget, evaluate.Error.Message, StringComparison.Ordinal);
            Assert.Null(evaluate.Result);

            Assert.Equal(0, probe.Calls);
            lock (logs)
            {
                Assert.Contains(logs, line => line.Contains("Denied 'enforcement.status' for uid:1001: private read", StringComparison.Ordinal));
                Assert.Contains(logs, line => line.Contains("Denied 'enforcement.receipts' for uid:1001: private read", StringComparison.Ordinal));
                Assert.Contains(logs, line => line.Contains("Denied 'enforcement.evaluate' for uid:1001: write", StringComparison.Ordinal));
                Assert.DoesNotContain(logs, line => line.Contains(SecretTarget, StringComparison.Ordinal));
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    /// <summary>
    /// The Linux daemon wiring (no enforcement handlers registered): root and the install owner pass
    /// authorization and get upstream's <c>not_supported</c>; a second user is refused first.
    /// </summary>
    [Theory]
    [InlineData(0u, IpcErrorCodes.NotSupported)]
    [InlineData(Owner, IpcErrorCodes.NotSupported)]
    [InlineData(Other, IpcErrorCodes.Unauthorized)]
    public async Task DaemonWithoutEnforcementAnswersNotSupportedOnlyToRootAndOwner(uint uid, string expectedCode)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = LinuxServicePaths.ForRoot(temp.Path);
        var dispatcher = new IpcRequestDispatcher(
            new IpcRequestHandlers
            {
                SnapshotProvider = () => (ConnectionSnapshot?)null,
                HealthProvider = Health,
            },
            writeGateOpen: () => true);
        var transport = new UnixSocketIpcTransport(paths, _ => PeerAuthorization.Decide(uid, OwnerOnly, UnixAccountRange.Linux));

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(dispatcher, _ => { }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            foreach (var command in EnforcementCommands)
            {
                var reply = await RequestAsync(paths.IpcSocketPath, command, command == IpcCommandTypes.EnforcementEvaluate ? EvaluatePayload() : null, cts.Token);
                Assert.False(reply!.Ok, command);
                Assert.Equal(expectedCode, reply.Error!.Code);
                Assert.Null(reply.Result);
                if (expectedCode == IpcErrorCodes.NotSupported)
                {
                    Assert.Contains("not available in this build", reply.Error.Message, StringComparison.Ordinal);
                }
            }
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    /// <summary>
    /// Real second account, real SO_PEERCRED: the three commands are refused with <c>unauthorized</c>,
    /// the handlers are never called, and public health still answers.
    /// </summary>
    [Fact]
    public async Task RealSecondUidGetsUnauthorizedForEnforcementCommandsOverSoPeerCred()
    {
        var user = Environment.GetEnvironmentVariable("AXIOM_TEST_SECOND_USER");
        if (!OperatingSystem.IsLinux() || string.IsNullOrWhiteSpace(user))
        {
            return; // opt-in: needs a throwaway account and passwordless sudo
        }

        const UnixFileMode Traversable = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

        // /dev/shm: the throwaway user's home is not traversable and the test temp dir is 0700.
        var root = Path.Combine("/dev/shm", "axiom-enf-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        File.SetUnixFileMode(root, Traversable);
        try
        {
            var paths = LinuxServicePaths.ForRoot(root);
            Directory.CreateDirectory(paths.RunDirectory);
            File.SetUnixFileMode(paths.RunDirectory, Traversable);
            var logs = new List<string>();
            var probe = new Probe();
            var me = geteuid();
            var policy = new PeerPolicy(OwnerUid: me, AdminGroupMayWrite: true, _ => false);
            var seen = new List<uint?>();
            var transport = new UnixSocketIpcTransport(paths, uid =>
            {
                lock (seen) { seen.Add(uid); }
                return PeerAuthorization.Decide(uid, policy, UnixAccountRange.Linux);
            });

            using var cts = new CancellationTokenSource(Timeout);
            var server = transport.RunAsync(probe.Dispatcher(line => { lock (logs) { logs.Add(line); } }), line => { lock (logs) { logs.Add(line); } }, cts.Token);
            try
            {
                await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);
                var client = Path.Combine(root, "client.py");
                await File.WriteAllTextAsync(client, ClientScript, cts.Token);
                File.SetUnixFileMode(client, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

                var output = await RunAsOtherUserAsync(user, client, paths.IpcSocketPath, cts.Token);
                var replies = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(line => JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options)!)
                    .ToList();
                Assert.Equal(4, replies.Count);

                Assert.True(replies[0].Ok); // serviceHealth
                Assert.DoesNotContain("enforcement", replies[0].Result!.Value.GetRawText(), StringComparison.OrdinalIgnoreCase);
                foreach (var denied in replies.Skip(1))
                {
                    Assert.False(denied.Ok);
                    Assert.Equal(IpcErrorCodes.Unauthorized, denied.Error!.Code);
                    Assert.Null(denied.Result);
                    Assert.DoesNotContain(SecretTarget, denied.Error.Message, StringComparison.Ordinal);
                }

                Assert.Contains("discloses machine-wide activity", replies[1].Error!.Message, StringComparison.Ordinal); // enforcement.status
                Assert.Contains("discloses machine-wide activity", replies[2].Error!.Message, StringComparison.Ordinal); // enforcement.receipts
                Assert.Contains("changes machine-wide settings", replies[3].Error!.Message, StringComparison.Ordinal); // enforcement.evaluate

                Assert.Equal(0, probe.Calls);
                lock (seen)
                {
                    Assert.NotEmpty(seen);
                    Assert.All(seen, uid => Assert.True(uid is { } value && value != me && value >= 1000, "peer uid must be the throwaway account's"));
                }

                lock (logs)
                {
                    Assert.Contains(logs, line => line.Contains("Denied 'enforcement.status'", StringComparison.Ordinal) && line.Contains("private read", StringComparison.Ordinal));
                    Assert.Contains(logs, line => line.Contains("Denied 'enforcement.receipts'", StringComparison.Ordinal) && line.Contains("private read", StringComparison.Ordinal));
                    Assert.Contains(logs, line => line.Contains("Denied 'enforcement.evaluate'", StringComparison.Ordinal) && line.Contains("write", StringComparison.Ordinal));
                    Assert.DoesNotContain(logs, line => line.Contains(SecretTarget, StringComparison.Ordinal));
                }
            }
            finally
            {
                await cts.CancelAsync();
                await server;
            }
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>Health, then the three enforcement commands, over fresh connections; one raw JSON reply per line.</summary>
    private const string ClientScript = """
        import json, socket, sys, uuid
        path = sys.argv[1]
        evaluate = {"requestId": "req-1", "agentId": "opencode", "kind": "readFile", "target": "/home/owner/.ssh/id_ed25519-secret-target"}
        for command, payload in [("serviceHealth", None), ("enforcement.status", None), ("enforcement.receipts", None), ("enforcement.evaluate", evaluate)]:
            envelope = {"version": 1, "id": str(uuid.uuid4()), "type": command}
            if payload is not None:
                envelope["payload"] = payload
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(10)
                client.connect(path)
                client.sendall((json.dumps(envelope) + "\n").encode())
                data = b""
                while b"\n" not in data:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            print(data.split(b"\n", 1)[0].decode())
        """;

    private static async Task<string> RunAsOtherUserAsync(string user, string script, string socketPath, CancellationToken ct)
    {
        var info = new ProcessStartInfo("sudo")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in new[] { "-n", "-u", user, "python3", "-I", script, socketPath })
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        Assert.True(process.ExitCode == 0, $"sudo -n -u {user} python3 failed ({process.ExitCode}): {await stderr}");
        return await stdout;
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

    [DllImport("libc")]
    private static extern uint geteuid();

    /// <summary>Dispatcher whose three enforcement handlers count every call.</summary>
    private sealed class Probe
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

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
                        Error = "Access to the path '/var/lib/axiom/secret-policy.json' is denied.",
                    });
                },
                EnforcementReceipts = _ =>
                {
                    Interlocked.Increment(ref _calls);
                    return Task.FromResult(new EnforcementReceiptsSnapshotDto { ChainValid = true, Total = 0, Receipts = [] });
                },
                EnforcementEvaluate = (request, _, _) =>
                {
                    Interlocked.Increment(ref _calls);
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
