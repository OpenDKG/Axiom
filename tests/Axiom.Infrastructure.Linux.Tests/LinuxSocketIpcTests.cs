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
/// The Linux authorization policy over a real Unix domain socket with real SO_PEERCRED uids:
/// the installing uid gets every class; a second uid (a throwaway account, run through
/// <c>sudo -n -u</c>) gets public health only and <c>unauthorized</c> for private reads and writes.
/// The second-uid test runs only when <c>AXIOM_TEST_SECOND_USER</c> names an existing account
/// that <c>sudo -n</c> can switch to (docs/LINUX_TEST_REPORT.md records the run).
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public sealed class LinuxSocketIpcTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Fact]
    public async Task InstallingUidGetsPrivateReadsAndWritesOverSoPeerCred()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = LinuxServicePaths.ForRoot(temp.Path);
        var logs = new List<string>();
        var me = geteuid();
        var policy = new PeerPolicy(OwnerUid: me, AdminGroupMayWrite: true, _ => false);
        uint? seen = null;
        var transport = new UnixSocketIpcTransport(paths, uid =>
        {
            seen = uid;
            return PeerAuthorization.Decide(uid, policy, UnixAccountRange.Linux);
        });

        using var cts = new CancellationTokenSource(Timeout);
        var server = transport.RunAsync(PrivateDispatcher(line => { lock (logs) { logs.Add(line); } }), line => { lock (logs) { logs.Add(line); } }, cts.Token);
        try
        {
            await WaitForSocketAsync(paths.IpcSocketPath, cts.Token);

            var health = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.ServiceHealth, cts.Token);
            Assert.True(health!.Ok);
            Assert.Equal("secret-last-error", health.Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options)!.LastError);
            Assert.Equal(me, seen);

            // Private reads and writes pass authorization and reach the handlers (which answer with their own errors here).
            var snapshot = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.Snapshot, cts.Token);
            Assert.Equal(IpcErrorCodes.ServiceUnavailable, snapshot!.Error!.Code);
            var history = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.HistoryQuery, cts.Token);
            Assert.Equal(IpcErrorCodes.InvalidRequest, history!.Error!.Code);
            var configure = await RequestAsync(paths.IpcSocketPath, IpcCommandTypes.PrivacyConfigure, cts.Token);
            Assert.NotEqual(IpcErrorCodes.Unauthorized, configure!.Error?.Code);
            Assert.Contains("SO_PEERCRED", transport.Prepare(), StringComparison.Ordinal);
        }
        finally
        {
            await cts.CancelAsync();
            await server;
        }
    }

    [Fact]
    public async Task SecondUidGetsPublicHealthOnlyOverSoPeerCred()
    {
        var user = Environment.GetEnvironmentVariable("AXIOM_TEST_SECOND_USER");
        if (!OperatingSystem.IsLinux() || string.IsNullOrWhiteSpace(user))
        {
            return; // opt-in: needs a throwaway account and passwordless sudo
        }

        // /dev/shm: the throwaway user's home is not traversable and the test temp dir is 0700.
        var root = Path.Combine("/dev/shm", "axiom-ipc-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        try
        {
            var paths = LinuxServicePaths.ForRoot(root);
            Directory.CreateDirectory(paths.RunDirectory);
            File.SetUnixFileMode(paths.RunDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
            var logs = new List<string>();
            var policy = new PeerPolicy(OwnerUid: geteuid(), AdminGroupMayWrite: true, _ => false);
            var seen = new List<uint?>();
            var transport = new UnixSocketIpcTransport(paths, uid =>
            {
                lock (seen) { seen.Add(uid); }
                return PeerAuthorization.Decide(uid, policy, UnixAccountRange.Linux);
            });

            using var cts = new CancellationTokenSource(Timeout);
            var server = transport.RunAsync(PrivateDispatcher(line => { lock (logs) { logs.Add(line); } }), line => { lock (logs) { logs.Add(line); } }, cts.Token);
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
                Assert.Equal(7, replies.Count);

                var health = replies[0];
                Assert.True(health.Ok);
                var redacted = health.Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options)!;
                Assert.Equal(0, redacted.ConnectionCount);
                Assert.Null(redacted.LastError);
                Assert.Equal([IpcCommandAccess.HealthRedactedNote], redacted.Limitations);
                Assert.True(replies[1].Ok); // capabilities
                foreach (var denied in replies.Skip(2))
                {
                    Assert.False(denied.Ok);
                    Assert.Equal(IpcErrorCodes.Unauthorized, denied.Error!.Code);
                    Assert.Contains("may only read public service health", denied.Error.Message, StringComparison.Ordinal);
                }

                Assert.Contains("discloses machine-wide activity", replies[2].Error!.Message, StringComparison.Ordinal); // snapshot
                Assert.Contains("discloses machine-wide activity", replies[3].Error!.Message, StringComparison.Ordinal); // history.query
                Assert.Contains("discloses machine-wide activity", replies[4].Error!.Message, StringComparison.Ordinal); // diagnostics.export
                Assert.Contains("changes machine-wide settings", replies[5].Error!.Message, StringComparison.Ordinal); // privacy.configure
                Assert.Contains("changes machine-wide settings", replies[6].Error!.Message, StringComparison.Ordinal); // rule.apply

                lock (seen)
                {
                    Assert.All(seen, uid => Assert.True(uid is { } value && value != geteuid() && value >= 1000, "peer uid must be the throwaway account's"));
                }

                lock (logs)
                {
                    Assert.Contains(logs, line => line.Contains("connected with public health access only", StringComparison.Ordinal));
                    Assert.Contains(logs, line => line.Contains("Denied 'history.query'", StringComparison.Ordinal) && line.Contains("private read", StringComparison.Ordinal));
                    Assert.Contains(logs, line => line.Contains("Denied 'rule.apply'", StringComparison.Ordinal) && line.Contains("write", StringComparison.Ordinal));
                    Assert.DoesNotContain(logs, line => line.Contains("handler reached", StringComparison.Ordinal));
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

    /// <summary>Seven requests in order over fresh connections; one raw JSON reply per line.</summary>
    private const string ClientScript = """
        import json, socket, sys, uuid
        path = sys.argv[1]
        for command in ["serviceHealth", "capabilities", "snapshot", "history.query", "diagnostics.export", "privacy.configure", "rule.apply"]:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(10)
                client.connect(path)
                client.sendall((json.dumps({"version": 1, "id": str(uuid.uuid4()), "type": command}) + "\n").encode())
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
                Limitations = ["secret limitation /home/alice/app"],
                LastError = "secret-last-error",
            },
            HistoryQuery = (_, _) => throw new InvalidOperationException("history handler reached"),
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
            return null;
        }
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
}
