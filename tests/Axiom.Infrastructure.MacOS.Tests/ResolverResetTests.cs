// SPDX-License-Identifier: GPL-3.0-or-later
using System.Buffers.Binary;
using Axiom.Infrastructure.MacOS;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// mDNSResponder reset after a new AxiomFilter instance: once per new instance, never for a
/// reconnect of the same instance or a daemon restart that finds it again, coalesced, and with a
/// signaller fake (no process is ever signalled by these tests). Pure logic, any OS.
/// </summary>
public sealed class ResolverResetTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);

    private static readonly FilterInstanceIdentity A = new(412, 1_763_460_000, 123_456);

    private static readonly FilterInstanceIdentity B = new(530, 1_763_460_100, 7);

    [Fact]
    public void IdentityRoundTripsAndRejectsDamagedMarkers()
    {
        Assert.Equal("412@1763460000.123456", A.ToString());
        Assert.Equal(A, FilterInstanceIdentity.TryParse(A + "\n"));
        Assert.Null(FilterInstanceIdentity.TryParse(null));
        Assert.Null(FilterInstanceIdentity.TryParse(""));
        Assert.Null(FilterInstanceIdentity.TryParse("412"));
        Assert.Null(FilterInstanceIdentity.TryParse("-1@5.0"));
        Assert.Null(FilterInstanceIdentity.TryParse("412@x.1"));
        Assert.NotEqual(A, A with { StartMicroseconds = 123_457 }); // same pid, other process
    }

    [Fact]
    public void NewInstanceSchedulesOneResetAfterTheDelay()
    {
        var policy = new ResolverResetPolicy(null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
        Assert.True(policy.Observe(A, T0));
        Assert.False(policy.TakeDue(T0.AddSeconds(4.9)));
        Assert.True(policy.TakeDue(T0.AddSeconds(5)));
        Assert.False(policy.TakeDue(T0.AddSeconds(6)));
        Assert.False(policy.TakeDue(T0.AddMinutes(10)));
    }

    [Fact]
    public void ReconnectOfTheSameInstanceSendsNothing()
    {
        var policy = new ResolverResetPolicy(null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
        Assert.True(policy.Observe(A, T0));
        Assert.True(policy.TakeDue(T0.AddSeconds(5)));
        Assert.False(policy.Observe(A, T0.AddSeconds(30)));
        Assert.False(policy.Observe(A, T0.AddMinutes(5)));
        Assert.Null(policy.DueAt);
    }

    [Fact]
    public void DaemonRestartWithThePersistedSameInstanceSendsNothing()
    {
        var policy = new ResolverResetPolicy(A, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
        Assert.False(policy.Observe(A, T0));
        Assert.False(policy.TakeDue(T0.AddMinutes(1)));
    }

    [Fact]
    public void DaemonRestartFindingAnotherInstanceSends()
    {
        var policy = new ResolverResetPolicy(A, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
        Assert.True(policy.Observe(B, T0));
        Assert.True(policy.TakeDue(T0.AddSeconds(5)));
    }

    [Fact]
    public void FirstEverSeenWithoutMarkerSendsOnce()
    {
        var policy = new ResolverResetPolicy(null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
        Assert.True(policy.Observe(A, T0));
        Assert.False(policy.Observe(A, T0.AddSeconds(1)));
        Assert.True(policy.TakeDue(T0.AddSeconds(5)));
        Assert.False(policy.TakeDue(T0.AddSeconds(20)));
    }

    [Fact]
    public void TwoNewInstancesBeforeTheResetCoalesceIntoOneSendAfterTheLatest()
    {
        var policy = new ResolverResetPolicy(null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
        Assert.True(policy.Observe(A, T0));
        Assert.True(policy.Observe(B, T0.AddSeconds(3)));
        Assert.False(policy.TakeDue(T0.AddSeconds(5)));
        Assert.True(policy.TakeDue(T0.AddSeconds(8)));
        Assert.False(policy.TakeDue(T0.AddSeconds(9)));
    }

    [Fact]
    public void NewInstanceRightAfterASendIsDeferredToTheMinimumIntervalNotDropped()
    {
        var policy = new ResolverResetPolicy(null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
        policy.Observe(A, T0);
        Assert.True(policy.TakeDue(T0.AddSeconds(5)));
        Assert.True(policy.Observe(B, T0.AddSeconds(6)));
        Assert.False(policy.TakeDue(T0.AddSeconds(11)));
        Assert.True(policy.TakeDue(T0.AddSeconds(15)));
    }

    [Fact]
    public void CoordinatorPersistsTheInstanceOwnerOnlyAndSurvivesARestart()
    {
        using var dir = new TempDirectory();
        var marker = Path.Combine(dir.Path, "filter-instance");
        var clock = new ManualTimeProvider(T0);
        var signaller = new FakeSignaller();
        var log = new List<string>();

        var first = new ResolverResetCoordinator(marker, signaller, clock, log.Add);
        first.FilterConnected(A);
        Assert.False(first.Tick());
        clock.Advance(ResolverResetPolicy.DefaultDelay);
        Assert.True(first.Tick());
        Assert.Equal(1, signaller.Calls);
        Assert.Equal(A + "\n", File.ReadAllText(marker));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(marker));
        }

        Assert.Contains(log, line => line.Contains("Sent SIGHUP to mDNSResponder", StringComparison.Ordinal)
                                     && line.Contains("first seen", StringComparison.Ordinal));

        // Daemon restart (new coordinator), same filter instance reconnects three times: nothing.
        var restarted = new ResolverResetCoordinator(marker, signaller, clock, log.Add);
        for (var i = 0; i < 3; i++)
        {
            restarted.FilterConnected(A);
            clock.Advance(TimeSpan.FromMinutes(1));
            Assert.False(restarted.Tick());
        }

        Assert.Equal(1, signaller.Calls);

        // A new instance (disable/enable, upgrade) after the restart: exactly one more.
        restarted.FilterConnected(B);
        clock.Advance(ResolverResetPolicy.DefaultDelay);
        Assert.True(restarted.Tick());
        Assert.False(restarted.Tick());
        Assert.Equal(2, signaller.Calls);
        Assert.Contains(log, line => line.Contains($"replaced {A}", StringComparison.Ordinal));
    }

    [Fact]
    public void SignalFailureIsLoggedAndNotFatal()
    {
        using var dir = new TempDirectory();
        var clock = new ManualTimeProvider(T0);
        var signaller = new FakeSignaller { Throw = true };
        var log = new List<string>();
        var coordinator = new ResolverResetCoordinator(Path.Combine(dir.Path, "m"), signaller, clock, log.Add);
        coordinator.FilterConnected(A);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(coordinator.Tick());
        Assert.Contains(log, line => line.StartsWith("Could not send SIGHUP to mDNSResponder", StringComparison.Ordinal));
        Assert.False(coordinator.Tick());
    }

    [Fact]
    public void UnreadableIdentitySchedulesNothing()
    {
        using var dir = new TempDirectory();
        var clock = new ManualTimeProvider(T0);
        var signaller = new FakeSignaller();
        var coordinator = new ResolverResetCoordinator(Path.Combine(dir.Path, "m"), signaller, clock, _ => { });
        coordinator.FilterConnected(null);
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.False(coordinator.Tick());
        Assert.Equal(0, signaller.Calls);
    }

    [Fact]
    public void DamagedMarkerCountsAsNoMarker()
    {
        using var dir = new TempDirectory();
        var marker = Path.Combine(dir.Path, "filter-instance");
        File.WriteAllText(marker, "garbage");
        var clock = new ManualTimeProvider(T0);
        var signaller = new FakeSignaller();
        var coordinator = new ResolverResetCoordinator(marker, signaller, clock, _ => { });
        Assert.Null(coordinator.Policy.LastSeen);
        coordinator.FilterConnected(A);
        clock.Advance(TimeSpan.FromSeconds(5));
        Assert.True(coordinator.Tick());
    }

    [Fact]
    public void TargetIsSelectedByExactExecutablePathNotByName()
    {
        var paths = new Dictionary<int, string>
        {
            [1] = "/sbin/launchd",
            [88] = "/usr/sbin/mDNSResponder",
            [89] = "/usr/sbin/mDNSResponderHelper",
            [90] = "/tmp/mDNSResponder",
            [91] = "/usr/sbin/mDNSResponder ",
            [92] = string.Empty,
        };
        Assert.Equal([88], MDnsResponderSignaller.SelectTargets(paths.Keys, pid => paths[pid]));
        Assert.Empty(MDnsResponderSignaller.SelectTargets([90, 92], pid => paths[pid]));
    }

    [Fact]
    public void StartTimeIsReadFromProcBsdInfo()
    {
        var buffer = new byte[LibProcLayout.BsdInfoSize];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(120), 1_763_460_000);
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(128), 123_456);
        Assert.Equal((1_763_460_000L, 123_456L), LibProcLayout.ParseStartTime(buffer));
        Assert.Null(LibProcLayout.ParseStartTime(new byte[LibProcLayout.BsdInfoSize]));
        Assert.Null(LibProcLayout.ParseStartTime(new byte[100]));
    }

    [Fact]
    public void MarkerLivesInTheDaemonDataDirectory()
    {
        var paths = MacServicePaths.ForRoot(Path.Combine(Path.GetTempPath(), "axiom-root"));
        Assert.Equal(Path.Combine(paths.MachineDataDirectory, "filter-instance"), paths.FilterInstanceMarkerFile);
    }

    private sealed class FakeSignaller : IResolverSignaller
    {
        public int Calls { get; private set; }

        public bool Throw { get; init; }

        public ResolverSignalResult Signal()
        {
            Calls++;
            if (Throw)
            {
                throw new InvalidOperationException("no permission");
            }

            return new ResolverSignalResult(true, [88], "ok");
        }
    }
}
