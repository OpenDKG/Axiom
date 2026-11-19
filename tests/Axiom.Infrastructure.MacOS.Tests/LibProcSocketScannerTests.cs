// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Infrastructure.MacOS.Dns;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Monitoring;
using Axiom.Infrastructure.MacOS.ProcessIdentity;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>Review #10: one libproc pass per 2 s shared by the connection poll and DNS attribution.</summary>
public sealed class LibProcSocketScannerTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ConnectionPollAtOneSecondMakesOnePassPerTwoSeconds()
    {
        var time = new ManualTimeProvider(Start);
        var passes = 0;
        var scanner = new LibProcSocketScanner(() => { passes++; return [Socket(10, 50000)]; }, time);
        var source = new MacConnectionSource(new FlowTable(), new FilterStatus(), PathOnlyIdentitySource.Instance, scanner.Current, time);

        // Ten 1 s polls (the fallback's PollInterval) cost 5 passes, not 10.
        for (var poll = 0; poll < 10; poll++)
        {
            Assert.Single(source.Capture(CancellationToken.None).Connections);
            time.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.Equal(5, passes);
        Assert.Equal(5, scanner.Passes);
    }

    [Fact]
    public void DnsLookupReusesThePollPassAndRefreshesOnMissAtMostTwicePerSecond()
    {
        if (!OperatingSystem.IsMacOS())
        {
            // MacDnsProcessLookup is [SupportedOSPlatform("macos")]; the scanner contract is checked directly.
            var passesOnly = 0;
            var time = new ManualTimeProvider(Start);
            var scanner = new LibProcSocketScanner(() => { passesOnly++; return [Socket(10, 50000)]; }, time);
            _ = scanner.Current();
            _ = scanner.Current();
            Assert.Equal(1, passesOnly);
            _ = scanner.Refresh();
            Assert.Equal(1, passesOnly);
            time.Advance(LibProcSocketScanner.RefreshFloor);
            _ = scanner.Refresh();
            _ = scanner.Refresh();
            Assert.Equal(2, passesOnly);
            time.Advance(LibProcSocketScanner.Lifetime);
            _ = scanner.Current();
            Assert.Equal(3, passesOnly);
            return;
        }

        var passes = 0;
        var clock = new ManualTimeProvider(Start);
        var shared = new LibProcSocketScanner(() => { passes++; return [Socket(10, 50000)]; }, clock);
        var source = new MacConnectionSource(new FlowTable(), new FilterStatus(), PathOnlyIdentitySource.Instance, shared.Current, clock);
        var lookup = new MacDnsProcessLookup(shared);

        source.Capture(CancellationToken.None);
        Assert.Equal(10, lookup.FindOwningProcess(new IPEndPoint(IPAddress.Loopback, 50000), tcp: false));
        Assert.Equal(1, passes);

        // A miss asks for a refresh, but not twice within 500 ms.
        Assert.Equal(0, lookup.FindOwningProcess(new IPEndPoint(IPAddress.Loopback, 60000), tcp: false));
        Assert.Equal(0, lookup.FindOwningProcess(new IPEndPoint(IPAddress.Loopback, 60001), tcp: false));
        Assert.Equal(1, passes);
        clock.Advance(LibProcSocketScanner.RefreshFloor);
        Assert.Equal(0, lookup.FindOwningProcess(new IPEndPoint(IPAddress.Loopback, 60000), tcp: false));
        Assert.Equal(2, passes);
    }

    private static LibProcSocket Socket(int pid, int port) =>
        new(pid, false, IPAddress.Loopback, port, IPAddress.Any, 0, -1);
}
