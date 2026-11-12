// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.CompilerServices;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

public sealed class NftEnforcementSupervisorTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 12, 12, 0, 0, TimeSpan.Zero);

    private sealed class Harness : IDisposable
    {
        public TempDirectory Dir { get; } = new();

        public FakeNftRunner Nft { get; } = new();

        public FakeCgroupFs Fs { get; } = new();

        public CollectingSink Sink { get; } = new();

        public ManualTimeProvider Time { get; } = new(Start);

        public List<string> Log { get; } = [];

        public NftFirewallPolicyAdapter Adapter { get; }

        public Harness()
        {
            Fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
            Fs.Cgroups.Add("system.slice/cron.service");
            Fs.Processes[500] = ("/usr/bin/curl", "system.slice/cron.service");
            Adapter = new NftFirewallPolicyAdapter(new NftEnginePaths(Path.Combine(Dir.Path, "filter")), new NftTable(Nft), new AppCgroupManager(Fs), Sink, () => true, Time);
        }

        public NftEnforcementSupervisor Supervisor(Func<NftTraceMonitor>? trace = null) =>
            new(Adapter, new NftTable(Nft), trace, Log.Add, Time)
            {
                AttributionInterval = TimeSpan.FromMilliseconds(20),
                WatchInterval = TimeSpan.FromMilliseconds(20),
                TraceRestartDelay = TimeSpan.FromMilliseconds(5),
            };

        public void Dispose()
        {
            Adapter.Dispose();
            Dir.Dispose();
        }
    }

    [Fact]
    public async Task Watcher_republishes_when_the_table_vanishes_and_attribution_reports_system_service_moves()
    {
        using var h = new Harness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None);
        var supervisor = h.Supervisor();

        // Table intact: nothing to do.
        Assert.False(await supervisor.WatchOnceAsync(CancellationToken.None));

        // Someone flushed the ruleset.
        h.Nft.TableGeneration = null;
        Assert.True(await supervisor.WatchOnceAsync(CancellationToken.None));
        Assert.NotNull(h.Nft.TableGeneration);
        Assert.Equal(1, supervisor.Republishes);
        Assert.Equal(1, supervisor.Degradations);
        Assert.Contains(h.Log, line => line.Contains("disappeared", StringComparison.Ordinal) && line.Contains("enforcement degraded", StringComparison.Ordinal));
        Assert.Contains(h.Log, line => line.StartsWith("Republished table inet axiom generation", StringComparison.Ordinal) && line.EndsWith("enforcement verified.", StringComparison.Ordinal));
        Assert.Equal(FilterEnforcementState.Verified, h.Adapter.Enforcement!.State);
        Assert.Equal(2, h.Adapter.Enforcement.AckedGeneration);

        // nft itself gone: degraded at once, nothing republished.
        h.Nft.ListFailure = new System.ComponentModel.Win32Exception(2, "No such file or directory");
        Assert.False(await supervisor.WatchOnceAsync(CancellationToken.None));
        Assert.Equal(FilterEnforcementState.Degraded, h.Adapter.Enforcement!.State);
        Assert.False(h.Adapter.Enforcement.Connected);
        Assert.Contains(h.Log, line => line.Contains("nft is unavailable", StringComparison.Ordinal) && line.Contains("enforcement degraded", StringComparison.Ordinal));
        h.Nft.ListFailure = null;
        Assert.False(await supervisor.WatchOnceAsync(CancellationToken.None));

        // A new curl process appears in a system service between polls: the 1 s loop herds and reports it.
        h.Fs.Processes[501] = ("/usr/bin/curl", "system.slice/cron.service");
        Assert.True(supervisor.AttributeOnce());
        Assert.StartsWith("axiom.slice/a-", h.Fs.Processes[501].Cgroup, StringComparison.Ordinal);
        Assert.Contains(h.Log, line => line.Contains("pid 501 (/usr/bin/curl) moved from SystemService cgroup system.slice/cron.service", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Run_publishes_at_start_runs_the_trace_monitor_and_tears_down_on_stop()
    {
        using var h = new Harness();
        await h.Adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None);
        var starts = 0;
        var supervisor = h.Supervisor(() =>
        {
            starts++;
            return new NftTraceMonitor(new EmptySource(), new NoLookup(), h.Adapter.DescribeRuleApp, h.Sink, h.Time);
        });

        using var cts = new CancellationTokenSource();
        var run = supervisor.RunAsync(cts.Token);
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while ((supervisor.AttributionPasses < 2 || starts < 2) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        cts.Cancel();
        await run;

        Assert.True(supervisor.StartGeneration > 0);
        Assert.True(starts >= 2, "trace monitor is restarted after it exits");
        Assert.True(supervisor.AttributionPasses >= 2);
        Assert.Null(h.Nft.TableGeneration);
        Assert.DoesNotContain(h.Fs.Cgroups, cgroup => cgroup.StartsWith("axiom.slice", StringComparison.Ordinal));
        Assert.Equal("system.slice/cron.service", h.Fs.Processes[500].Cgroup);
        Assert.Contains(h.Log, line => line.StartsWith("Published table inet axiom generation", StringComparison.Ordinal) && line.Contains("enforcement verified", StringComparison.Ordinal));
        Assert.Contains(h.Log, line => line.StartsWith("Enforcement limitation: Attribution is a 1 s loop", StringComparison.Ordinal));
        Assert.Contains(h.Log, line => line.StartsWith("Removed table inet axiom", StringComparison.Ordinal));
    }

    private sealed class EmptySource : INftTraceSource
    {
        public async IAsyncEnumerable<string> ReadLinesAsync([EnumeratorCancellation] CancellationToken ct)
        {
            await Task.Yield();
            yield break;
        }
    }

    private sealed class NoLookup : ISocketOwnerLookup
    {
        public SocketOwner? FindOwner(string protocol, string localAddress, int localPort) => null;
    }
}
