// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Linux.ProcFs;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class ProcConnectionSourceTests : IDisposable
{
    private const string TcpHeader =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "axiom-proc-" + Guid.NewGuid().ToString("N"));

    public ProcConnectionSourceTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "net"));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task Tcp_and_udp_rows_are_attributed_and_unattributed_sockets_stay_partial()
    {
        WriteTable("tcp",
            "0: 0100007F:1F90 0100007F:9C40 01 0 0 0 0 0 111 1 0 0 0 0 0 0",
            "1: 00000000:1F90 00000000:0000 0A 0 0 0 0 0 333 1 0 0 0 0 0 0",
            "2: 0100007F:9C40 08080808:01BB 01 0 0 0 0 0 112 1 0 0 0 0 0 0");
        WriteTable("tcp6");
        WriteTable("udp",
            "0: 00000000:0035 00000000:0000 07 0 0 0 0 0 222 1 0 0 0 0 0 0");
        WriteTable("udp6");

        CreateProcess(4242, "curl", [111, 333, 112], "/usr/bin/curl", 12345);

        var source = new ProcConnectionSource(_root);
        var snapshot = await source.CaptureAsync(CancellationToken.None);

        var accepted = Assert.Single(snapshot.Connections, row => row.LocalEndpoint == "127.0.0.1:8080");
        Assert.Equal("curl", accepted.AppDisplayName);
        Assert.Equal("/usr/bin/curl", accepted.AppPath);
        Assert.Equal(TransportProtocol.Tcp, accepted.Protocol);
        Assert.Equal("127.0.0.1:40000", accepted.RemoteEndpoint);
        Assert.Equal(ConnectionDirection.Inbound, accepted.Direction);
        Assert.Equal(DataQuality.Observed, accepted.Quality);
        Assert.True(accepted.IsLoopback);

        var client = Assert.Single(snapshot.Connections, row => row.LocalEndpoint == "127.0.0.1:40000");
        Assert.Equal(ConnectionDirection.Outbound, client.Direction);
        Assert.Equal("8.8.8.8:443", client.RemoteEndpoint);

        var listener = Assert.Single(snapshot.Connections, row => row.State == "Listen");
        Assert.Equal(ConnectionDirection.Inbound, listener.Direction);

        var unattributed = Assert.Single(snapshot.Connections, row => row.Protocol == TransportProtocol.Udp);
        Assert.Equal(TransportProtocol.Udp, unattributed.Protocol);
        Assert.Equal("0.0.0.0:53", unattributed.LocalEndpoint);
        Assert.Equal("—", unattributed.RemoteEndpoint);
        Assert.Equal(ConnectionDirection.Unknown, unattributed.Direction);
        Assert.Equal(DataQuality.Partial, unattributed.Quality);

        Assert.Equal(2, snapshot.ProcessCount);
        Assert.Contains(snapshot.Limitations, item => item.Contains("UDP direction", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_rebound_socket_with_a_new_inode_starts_a_new_first_seen_window()
    {
        WriteTable("tcp", "0: 0100007F:1F90 0100007F:0BB8 01 0 0 0 0 0 111 1 0 0 0 0 0 0");
        WriteTable("tcp6");
        WriteTable("udp");
        WriteTable("udp6");
        CreateProcess(4242, "curl", [111], "/usr/bin/curl", 12345);

        var source = new ProcConnectionSource(_root);
        var first = await source.CaptureAsync(CancellationToken.None);
        var firstSeen = Assert.Single(first.Connections).FirstObservedUtc;

        await Task.Delay(20);

        // Same pid, endpoints and process start time; only the socket inode changed.
        WriteTable("tcp", "0: 0100007F:1F90 0100007F:0BB8 01 0 0 0 0 0 222 1 0 0 0 0 0 0");
        CreateProcess(4242, "curl", [222], "/usr/bin/curl", 12345);

        var second = await source.CaptureAsync(CancellationToken.None);
        var reopened = Assert.Single(second.Connections);
        Assert.Equal("curl", reopened.AppDisplayName);

        Assert.True(
            reopened.FirstObservedUtc > firstSeen,
            "a new socket inode must not inherit the previous socket's first-seen time");
    }

    [Fact]
    public async Task A_socket_absent_from_a_capture_expires_and_starts_a_new_window()
    {
        WriteTable("tcp", "0: 0100007F:1F90 0100007F:0BB8 01 0 0 0 0 0 111 1 0 0 0 0 0 0");
        WriteTable("tcp6");
        WriteTable("udp");
        WriteTable("udp6");
        CreateProcess(4242, "curl", [111], "/usr/bin/curl", 12345);

        var source = new ProcConnectionSource(_root, firstSeenRetention: TimeSpan.Zero);
        var first = await source.CaptureAsync(CancellationToken.None);
        var firstSeen = Assert.Single(first.Connections).FirstObservedUtc;

        WriteTable("tcp");
        Assert.Empty((await source.CaptureAsync(CancellationToken.None)).Connections);

        await Task.Delay(20);
        WriteTable("tcp", "0: 0100007F:1F90 0100007F:0BB8 01 0 0 0 0 0 111 1 0 0 0 0 0 0");
        var third = await source.CaptureAsync(CancellationToken.None);

        Assert.True(
            Assert.Single(third.Connections).FirstObservedUtc > firstSeen,
            "an absent socket must be pruned instead of keeping its old first-seen time");
    }

    [Fact]
    public async Task A_recycled_pid_starts_a_new_first_seen_window()
    {
        WriteTable("tcp", "0: 0100007F:1F90 0100007F:0BB8 01 0 0 0 0 0 111 1 0 0 0 0 0 0");
        WriteTable("tcp6");
        WriteTable("udp");
        WriteTable("udp6");
        CreateProcess(4242, "curl", [111, 333, 112], "/usr/bin/curl", 12345);

        var source = new ProcConnectionSource(_root);
        var first = await source.CaptureAsync(CancellationToken.None);
        var firstSeen = Assert.Single(first.Connections).FirstObservedUtc;

        // Same PID and inode, different kernel start time: a different process instance.
        CreateProcess(4242, "curl", [111], "/usr/bin/curl", 99999);

        var second = await source.CaptureAsync(CancellationToken.None);
        var secondSeen = Assert.Single(second.Connections).FirstObservedUtc;

        Assert.True(secondSeen >= firstSeen);
        Assert.True(secondSeen > firstSeen);
    }

    [Fact]
    public void A_deleted_executable_keeps_its_path_without_the_kernel_suffix()
    {
        CreateProcess(4242, "old", [111], "/usr/bin/old (deleted)", 12345);

        var identity = new ProcProcessIdentityResolver(_root).Resolve(4242);

        Assert.Equal("/usr/bin/old", identity.ExecutablePath);
        Assert.True(identity.IsResolved);
    }

    [Fact]
    public void A_missing_pid_is_reported_as_unresolved()
    {
        var identity = new ProcProcessIdentityResolver(_root).Resolve(999999);

        Assert.False(identity.IsResolved);
        Assert.Equal(string.Empty, identity.ExecutablePath);
    }

    [Fact]
    public async Task Tcp_server_on_a_high_port_is_still_inbound()
    {
        WriteTable("tcp",
            "0: 00000000:C350 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 500 1 0000000000000000 100 0 0 10 0",
            "1: 0100007F:C350 0100007F:9C40 01 00000000:00000000 00:00000000 00000000 0 0 501 1 0000000000000000 100 0 0 10 0");
        WriteTable("tcp6");
        WriteTable("udp");
        WriteTable("udp6");
        CreateProcess(4242, "server", [500, 501], "/usr/bin/server", 12345);

        var snapshot = await new ProcConnectionSource(_root).CaptureAsync(CancellationToken.None);

        var accepted = Assert.Single(
            snapshot.Connections,
            row => row.LocalEndpoint.EndsWith(":50000", StringComparison.Ordinal) &&
                   row.State == "Established" &&
                   row.RemoteEndpoint != "—");
        Assert.Equal(ConnectionDirection.Inbound, accepted.Direction);
        Assert.Equal(DataQuality.Observed, accepted.Quality);
    }

    [Fact]
    public async Task A_socket_shared_by_two_processes_stays_unattributed()
    {
        WriteTable("tcp", "0: 0100007F:1F90 0100007F:0BB8 01 00000000:00000000 00:00000000 00000000 0 0 600 1 0000000000000000 100 0 0 10 0");
        WriteTable("tcp6");
        WriteTable("udp");
        WriteTable("udp6");
        CreateProcess(4242, "parent", [600], "/usr/bin/parent", 111);
        CreateProcess(4343, "child", [600], "/usr/bin/child", 222);

        var snapshot = await new ProcConnectionSource(_root).CaptureAsync(CancellationToken.None);

        var row = Assert.Single(snapshot.Connections);
        Assert.Equal(0, row.ProcessId);
        Assert.Equal(DataQuality.Partial, row.Quality);
        Assert.Contains(snapshot.Limitations, item => item.Contains("shared", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Missing_process_start_time_stays_unattributed()
    {
        WriteTable("tcp", "0: 0100007F:1F90 0100007F:0BB8 01 00000000:00000000 00:00000000 00000000 0 0 700 1 0000000000000000 100 0 0 10 0");
        WriteTable("tcp6");
        WriteTable("udp");
        WriteTable("udp6");
        CreateProcess(4242, "no-stat", [700], "/usr/bin/no-stat", 0, writeStat: false);

        var snapshot = await new ProcConnectionSource(_root).CaptureAsync(CancellationToken.None);

        var row = Assert.Single(snapshot.Connections);
        Assert.Equal(0, row.ProcessId);
        Assert.Equal(DataQuality.Partial, row.Quality);
        Assert.Contains(snapshot.Limitations, item => item.Contains("start time", StringComparison.OrdinalIgnoreCase));
    }

    private void WriteTable(string name, params string[] rows)
    {
        var content = TcpHeader + "\n" + string.Join('\n', rows) + (rows.Length > 0 ? "\n" : string.Empty);
        File.WriteAllText(Path.Combine(_root, "net", name), content);
    }

    private void CreateProcess(
        int pid,
        string comm,
        long[] inodes,
        string exeTarget,
        long startTime,
        bool writeStat = true)
    {
        var directory = Path.Combine(_root, pid.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Directory.CreateDirectory(Path.Combine(directory, "fd"));
        File.WriteAllText(Path.Combine(directory, "comm"), comm + "\n");
        var exePath = Path.Combine(directory, "exe");
        if (File.Exists(exePath))
        {
            File.Delete(exePath);
        }

        File.CreateSymbolicLink(exePath, exeTarget);

        for (var index = 0; index < inodes.Length; index++)
        {
            var fdPath = Path.Combine(directory, "fd", (index + 3).ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (File.Exists(fdPath))
            {
                File.Delete(fdPath);
            }

            File.CreateSymbolicLink(fdPath, $"socket:[{inodes[index]}]");
        }
        if (writeStat)
        {
            File.WriteAllText(
                Path.Combine(directory, "stat"),
                $"{pid} ({comm}) S 1 42 42 0 -1 4194304 10 0 0 0 5 0 0 0 20 0 1 0 {startTime} 0 0");
        }
    }
}
