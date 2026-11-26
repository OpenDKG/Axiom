// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Linux.Dns;
using Axiom.Infrastructure.Linux.Monitoring;
using Axiom.Infrastructure.Linux.ProcessIdentity;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class ProcNetAndIdentityTests
{
    private const string TcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
        "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
        "   1: 0A00000F:A1B2 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1\n" +
        "   2: 0A00000F:A1B3 5DB8D822:01BB 07 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 20 4 30 10 -1\n" +
        "garbage line\n";

    private const string Tcp6Table =
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
        "   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0\n" +
        "   1: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000000000000000 20 4 30 10 -1\n";

    [Fact]
    public void ParsesHexEndpointsStatesAndSkipsClosedRows()
    {
        var sockets = ProcNetTable.Parse(TcpTable, tcp: true);

        Assert.Equal(2, sockets.Count);
        Assert.Equal(IPAddress.Loopback, sockets[0].LocalAddress);
        Assert.Equal(53, sockets[0].LocalPort);
        Assert.Equal(ProcNetTable.TcpStateListen, sockets[0].TcpState);
        Assert.Equal(12345, sockets[0].Inode);
        Assert.Equal(IPAddress.Parse("15.0.0.10"), sockets[1].LocalAddress);
        Assert.Equal(IPAddress.Parse("34.216.184.93"), sockets[1].RemoteAddress);
        Assert.Equal(443, sockets[1].RemotePort);
        Assert.Equal(1000u, sockets[1].Uid);
        Assert.Equal("Established", ProcNetTable.TcpStateName(sockets[1].TcpState));
    }

    [Fact]
    public void ParsesIpv6AndMapsV4InV6ToV4()
    {
        var sockets = ProcNetTable.Parse(Tcp6Table, tcp: true);

        Assert.Equal(2, sockets.Count);
        Assert.Equal(IPAddress.IPv6Loopback, sockets[0].LocalAddress);
        Assert.Equal(22, sockets[0].LocalPort);
        Assert.Equal(IPAddress.Loopback, sockets[1].LocalAddress);
        Assert.Equal(8080, sockets[1].LocalPort);
        Assert.Equal(50000, sockets[1].RemotePort);
    }

    [Fact]
    public void SocketInodeLinksAreRecognised()
    {
        Assert.True(ProcNetTable.TryParseSocketInode("socket:[4242]", out var inode));
        Assert.Equal(4242, inode);
        Assert.False(ProcNetTable.TryParseSocketInode("/dev/null", out _));
        Assert.False(ProcNetTable.TryParseSocketInode("socket:[x]", out _));
        Assert.False(ProcNetTable.TryParseSocketInode(null, out _));
    }

    [Fact]
    public void StatParsingSurvivesSpacesInComm()
    {
        var (ppid, state) = ProcProcessIdentityResolver.ParseStat("4242 (my (odd) prog) S 1200 4242 4242 0 -1 4194560 0");
        Assert.Equal(1200, ppid);
        Assert.Equal('S', state);
        Assert.Null(ProcProcessIdentityResolver.ParseStat("broken").ParentProcessId);
    }

    [Fact]
    public void FakeProcTreeIsJoinedIntoConnections()
    {
        using var temp = new TempDirectory();
        var proc = Path.Combine(temp.Path, "proc");
        Directory.CreateDirectory(Path.Combine(proc, "net"));
        File.WriteAllText(Path.Combine(proc, "net", "tcp"), TcpTable);
        File.WriteAllText(Path.Combine(proc, "net", "udp"), string.Empty);

        var pid = Path.Combine(proc, "4242");
        Directory.CreateDirectory(Path.Combine(pid, "fd"));
        File.CreateSymbolicLink(Path.Combine(pid, "fd", "3"), "socket:[67890]");
        File.CreateSymbolicLink(Path.Combine(pid, "fd", "0"), "/dev/null");
        File.WriteAllText(Path.Combine(pid, "comm"), "curl\n");
        File.WriteAllText(Path.Combine(pid, "cmdline"), "curl\0https://example.org\0");
        File.WriteAllText(Path.Combine(pid, "stat"), "4242 (curl) S 1200 4242 4242 0 -1 4194560 0");
        File.WriteAllText(Path.Combine(pid, "status"), "Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\n");
        var parent = Path.Combine(proc, "1200");
        Directory.CreateDirectory(parent);
        File.WriteAllText(Path.Combine(parent, "comm"), "bash\n");
        File.WriteAllText(Path.Combine(parent, "stat"), "1200 (bash) S 1 1200 1200 0 -1 4194560 0");

        var sockets = ProcSocketScanner.Scan(proc);
        Assert.Equal(2, sockets.Count);
        Assert.Equal(4242, sockets.Single(socket => socket.Inode == 67890).ProcessId);
        Assert.Equal(0, sockets.Single(socket => socket.Inode == 12345).ProcessId);

        var source = new LinuxConnectionSource(() => sockets, new ProcProcessIdentityResolver(proc, TimeProvider.System, sanitiserTimeout: Regex.InfiniteMatchTimeout), TimeProvider.System, privileged: false);
        var snapshot = source.Capture(CancellationToken.None);

        Assert.Equal(LinuxConnectionSource.SourceName, snapshot.SourceName);
        Assert.Equal(2, snapshot.Connections.Count);
        var curl = snapshot.Connections.Single(connection => connection.ProcessId == 4242);
        Assert.Equal("curl", curl.AppDisplayName);
        Assert.Equal("34.216.184.93:443", curl.RemoteEndpoint);
        Assert.Equal("15.0.0.10:41394", curl.LocalEndpoint);
        Assert.Equal(ConnectionDirection.Outbound, curl.Direction);
        Assert.Equal("curl https://example.org", curl.CommandLine);
        Assert.Equal(1200, curl.ParentProcessId);
        Assert.Equal("bash", curl.ParentProcessName);
        Assert.Equal("bash(1200) > ?(1)", curl.ParentChain);
        Assert.Equal(DataQuality.Partial, curl.Quality);
        var listener = snapshot.Connections.Single(connection => connection.ProcessId == 0);
        Assert.Equal("uid 0", listener.AppDisplayName);
        Assert.Equal(ConnectionDirection.Inbound, listener.Direction);
        Assert.Equal("—", listener.RemoteEndpoint);
        Assert.Contains(snapshot.Limitations, limitation => limitation.Contains("not root", StringComparison.Ordinal));
        Assert.Equal(1, snapshot.ProcessCount);

        var lookup = new LinuxDnsProcessLookup(new ProcSocketScanner(() => sockets, TimeProvider.System), new ProcProcessIdentityResolver(proc, TimeProvider.System, sanitiserTimeout: Regex.InfiniteMatchTimeout));
        Assert.Equal(4242, lookup.FindOwningProcess(new IPEndPoint(IPAddress.Parse("15.0.0.10"), 41394), tcp: true));
        Assert.Equal(0, lookup.FindOwningProcess(new IPEndPoint(IPAddress.Loopback, 53), tcp: true));
        Assert.Equal(("curl", string.Empty), lookup.Describe(4242));
        Assert.Equal(1200, lookup.ParentProcessId(4242));
    }

    [Fact]
    public void CommandLineIsSanitisedWithArgumentBoundariesAndTheOwnersHome()
    {
        using var temp = new TempDirectory();
        var proc = Path.Combine(temp.Path, "proc");
        var pid = Path.Combine(proc, "4242");
        Directory.CreateDirectory(pid);
        File.WriteAllText(Path.Combine(pid, "comm"), "app\n");
        File.WriteAllText(Path.Combine(pid, "stat"), "4242 (app) S 1 4242 4242 0 -1 4194560 0");
        File.WriteAllText(Path.Combine(pid, "status"), "Name:\tapp\nUid:\t1000\t1000\t1000\t1000\n");
        File.WriteAllText(
            Path.Combine(pid, "cmdline"),
            "/home/tester/app\0--password\0hunter2\0--token\0two words\0--secret=more words\0-H\0Authorization: Bearer abc123\0");
        var passwd = Path.Combine(temp.Path, "passwd");
        File.WriteAllText(passwd, "root:x:0:0:root:/root:/bin/sh\ntester:x:1000:1000::/home/tester:/bin/sh\n");

        var identity = new ProcProcessIdentityResolver(proc, TimeProvider.System, passwd, Regex.InfiniteMatchTimeout).Resolve(4242, null);

        Assert.Equal(
            "~/app --password *** --token *** --secret=*** -H \"Authorization: Bearer ***\"",
            identity.CommandLine);
    }

    [Fact]
    public void HomeDirectoryLookupIsCachedBetweenProcessesAndRefreshedLater()
    {
        using var temp = new TempDirectory();
        var proc = Path.Combine(temp.Path, "proc");
        foreach (var id in new[] { 100, 101, 102, 103 })
        {
            var pid = Path.Combine(proc, id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Directory.CreateDirectory(pid);
            File.WriteAllText(Path.Combine(pid, "comm"), "app\n");
            File.WriteAllText(Path.Combine(pid, "stat"), $"{id} (app) S 1 {id} {id} 0 -1 4194560 0");
            File.WriteAllText(Path.Combine(pid, "status"), "Uid:\t1000\t1000\t1000\t1000\n");
            File.WriteAllText(Path.Combine(pid, "cmdline"), "app\0/home/first/a\0/home/second/b\0");
        }

        var passwd = Path.Combine(temp.Path, "passwd");
        File.WriteAllText(passwd, "tester:x:1000:1000::/home/first:/bin/sh\n");
        var time = new FakeTime(DateTimeOffset.UnixEpoch);
        var resolver = new ProcProcessIdentityResolver(proc, time, passwd, Regex.InfiniteMatchTimeout);
        Assert.Equal("app ~/a /home/second/b", resolver.Resolve(100, null).CommandLine);

        File.Delete(passwd);
        Assert.Equal("app ~/a /home/second/b", resolver.Resolve(101, null).CommandLine);

        File.WriteAllText(passwd, "tester:x:1000:1000::/home/second:/bin/sh\n");
        time.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal("app ~/a /home/second/b", resolver.Resolve(102, null).CommandLine);
        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal("app /home/first/a ~/b", resolver.Resolve(103, null).CommandLine);
    }

    [Fact]
    public void ScannerCachesForTwoSecondsAndRefreshesOnDemand()
    {
        var passes = 0;
        var time = new FakeTime(DateTimeOffset.UnixEpoch);
        var scanner = new ProcSocketScanner(() => { passes++; return []; }, time);

        scanner.Current();
        scanner.Current();
        Assert.Equal(1, passes);
        time.Advance(TimeSpan.FromMilliseconds(600));
        scanner.Refresh();
        Assert.Equal(2, passes);
        scanner.Refresh();
        Assert.Equal(2, passes);
        time.Advance(TimeSpan.FromSeconds(2));
        scanner.Current();
        Assert.Equal(3, passes);
    }

    [Fact]
    public void LiveProcFindsThisProcessesOwnListeningSocket()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(1);
        var port = ((IPEndPoint)listener.LocalEndPoint!).Port;

        var sockets = ProcSocketScanner.Scan("/proc");
        var mine = sockets.Single(socket => socket.Tcp && socket.LocalPort == port && socket.LocalAddress.Equals(IPAddress.Loopback));
        Assert.Equal(Environment.ProcessId, mine.ProcessId);
        Assert.Equal(ProcNetTable.TcpStateListen, mine.TcpState);

        var identity = new ProcProcessIdentityResolver().Resolve(Environment.ProcessId, null);
        Assert.NotEmpty(identity.Path);
        Assert.True(identity.ParentProcessId > 0);
    }

    private sealed class FakeTime(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now += delta;
    }
}
