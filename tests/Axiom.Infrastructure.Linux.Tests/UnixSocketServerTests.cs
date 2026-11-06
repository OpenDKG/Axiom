// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Infrastructure.Linux.Ipc;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class UnixSocketServerTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "axiom-socket-" + Guid.NewGuid().ToString("N"));

    private readonly string _socketPath;

    private readonly CancellationTokenSource _cancellation = new();

    private UnixSocketServer? _server;

    private Task? _running;

    public UnixSocketServerTests()
    {
        Directory.CreateDirectory(_directory);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(_directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        _socketPath = Path.Combine(_directory, "service.sock");
    }

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
        _cancellation.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task Health_request_round_trips_and_permissions_are_private()
    {
        await StartAsync(PosixIdentity.EffectiveUserId);

        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(_socketPath));
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(_directory));

        var client = CreateClient();
        var health = await client.SendAsync<ServiceHealth>(
            IpcCommandTypes.ServiceHealth, null, CancellationToken.None);

        Assert.Equal("running", health.Status);
        Assert.Equal("test-source", health.SourceName);
    }

    [Fact]
    public async Task A_different_uid_is_rejected_before_any_request_is_parsed()
    {
        if (!PosixIdentity.IsSuperUser)
        {
            // Without root the service must refuse to expose its socket to another uid at all.
            var refused = new UnixSocketServer(
                _socketPath,
                PosixIdentity.EffectiveUserId + 1000,
                CreateProcessor());
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                refused.RunAsync(_cancellation.Token));
            return;
        }

        await StartAsync(PosixIdentity.EffectiveUserId + 1000);
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.GroupExecute | UnixFileMode.OtherExecute,
            File.GetUnixFileMode(_directory));

        var client = CreateClient();
        var exception = await Assert.ThrowsAsync<IpcClientException>(() =>
            client.SendAsync<ServiceHealth>(IpcCommandTypes.ServiceHealth, null, CancellationToken.None));

        Assert.Equal(IpcErrorCodes.ServiceUnavailable, exception.Code);

        // The listener survives a rejected peer and still serves the allowed uid only.
        Assert.True(File.Exists(_socketPath));
    }

    [Fact]
    public async Task Oversized_request_is_rejected_before_json_parsing()
    {
        await StartAsync(PosixIdentity.EffectiveUserId);

        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(_socketPath));
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        var payload = Encoding.UTF8.GetBytes(new string('x', IpcProtocol.MaxMessageBytes + 64) + "\n");
        var read = IpcLineProtocol.ReadLineAsync(
            stream,
            IpcProtocol.MaxResponseBytes,
            CancellationToken.None);

        try
        {
            await stream.WriteAsync(payload);
            await stream.FlushAsync();
        }
        catch (IOException)
        {
            // The server may close immediately after reporting the size violation.
        }

        var line = await read;

        Assert.NotNull(line);
        var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options);
        Assert.NotNull(response);
        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.MessageTooLarge, response.Error!.Code);
    }

    [Fact]
    public async Task Unknown_command_is_rejected()
    {
        await StartAsync(PosixIdentity.EffectiveUserId);

        var client = CreateClient();
        var exception = await Assert.ThrowsAsync<IpcClientException>(() =>
            client.SendAsync<object>("axiom.exec", null, CancellationToken.None));

        Assert.Equal(IpcErrorCodes.UnknownCommand, exception.Code);
    }

    [Fact]
    public async Task Concurrent_clients_are_served_independently()
    {
        await StartAsync(PosixIdentity.EffectiveUserId);

        var requests = Enumerable.Range(0, 10).Select(async _ =>
        {
            var health = await CreateClient().SendAsync<ServiceHealth>(
                IpcCommandTypes.ServiceHealth, null, CancellationToken.None);
            return health.Status;
        });

        var results = await Task.WhenAll(requests);
        Assert.All(results, status => Assert.Equal("running", status));
    }

    [Fact]
    public async Task A_stale_file_at_the_socket_path_is_replaced()
    {
        await File.WriteAllTextAsync(_socketPath, "stale");

        await StartAsync(PosixIdentity.EffectiveUserId);

        var health = await CreateClient().SendAsync<ServiceHealth>(
            IpcCommandTypes.ServiceHealth, null, CancellationToken.None);
        Assert.Equal("running", health.Status);
    }

    [Fact]
    public async Task A_symlinked_socket_path_is_refused()
    {
        var target = Path.Combine(_directory, "target.sock");
        File.CreateSymbolicLink(_socketPath, target);

        _server = new UnixSocketServer(
            _socketPath,
            PosixIdentity.EffectiveUserId,
            CreateProcessor());

        await Assert.ThrowsAsync<IOException>(() =>
            _server.RunAsync(_cancellation.Token));
    }

    [Fact]
    public async Task A_refused_second_instance_does_not_unlink_the_live_socket()
    {
        await StartAsync(PosixIdentity.EffectiveUserId);

        var second = new UnixSocketServer(
            _socketPath,
            PosixIdentity.EffectiveUserId,
            CreateProcessor());

        await Assert.ThrowsAsync<IOException>(() => second.RunAsync(_cancellation.Token));
        await second.DisposeAsync();

        Assert.True(File.Exists(_socketPath));
        var health = await CreateClient().SendAsync<ServiceHealth>(
            IpcCommandTypes.ServiceHealth, null, CancellationToken.None);
        Assert.Equal("running", health.Status);
    }

    [Fact]
    public async Task Initialization_failure_leaves_no_endpoint_and_dispose_is_safe()
    {
        var path = $"/proc/axiom-init-failure-{Guid.NewGuid():N}/socket";
        var server = new UnixSocketServer(path, (uint)Environment.UserName.GetHashCode(), CreateProcessor());

        await Assert.ThrowsAnyAsync<Exception>(() => server.RunAsync(CancellationToken.None));
        await server.DisposeAsync();

        Assert.False(File.Exists(path));
        Assert.False(Directory.Exists(Path.GetDirectoryName(path)));
    }

    [Fact]
    public async Task A_populated_shared_socket_directory_is_refused_without_chmod()
    {
        var shared = Path.Combine(_directory, "shared");
        Directory.CreateDirectory(shared);
        await File.WriteAllTextAsync(Path.Combine(shared, "unrelated"), "keep");
        File.SetUnixFileMode(
            shared,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

        var socketPath = Path.Combine(shared, "service.sock");
        var server = new UnixSocketServer(
            socketPath,
            PosixIdentity.EffectiveUserId,
            CreateProcessor());

        await Assert.ThrowsAsync<IOException>(() => server.RunAsync(_cancellation.Token));
        await server.DisposeAsync();

        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherExecute,
            File.GetUnixFileMode(shared));
        Assert.True(File.Exists(Path.Combine(shared, "unrelated")));
    }

    private IpcPipeClient CreateClient() =>
        new(
            IpcPipe.Name,
            connectTimeout: TimeSpan.FromSeconds(2),
            requestTimeout: TimeSpan.FromSeconds(2),
            unixSocketPath: _socketPath);

    private async Task StartAsync(uint allowedUid)
    {
        _server = new UnixSocketServer(_socketPath, allowedUid, CreateProcessor());
        _running = _server.RunAsync(_cancellation.Token);

        for (var attempt = 0; attempt < 100 && !File.Exists(_socketPath); attempt++)
        {
            await Task.Delay(20);
        }

        Assert.True(File.Exists(_socketPath), "The server did not create its socket.");
    }

    private static IpcRequestProcessor CreateProcessor() =>
        new(
            snapshot: () => null,
            health: () => new ServiceHealth
            {
                Status = "running",
                UptimeSeconds = 5,
                SourceName = "test-source",
                PollIntervalSeconds = 1,
                ConnectionCount = 0,
                ProcessCount = 0,
            });
}
