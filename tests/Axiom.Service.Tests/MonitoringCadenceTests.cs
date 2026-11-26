// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Persistence;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Axiom.Service.Tests;

/// <summary>Runs the real monitoring loop on a manual clock and counts connection-table polls.</summary>
public sealed class MonitoringCadenceTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("axiom-cadence-").FullName;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task Without_clients_and_with_shield_off_polling_backs_off_to_ten_seconds()
    {
        await using var run = await StartAsync(shieldEnabled: false);
        await run.AdvanceAsync(seconds: 40); // past the 30 s grace period

        var polls = await run.CountPollsAsync(seconds: 60);

        Assert.InRange(polls, 5, 7);
    }

    [Fact]
    public async Task With_shield_on_polling_stays_at_one_second_without_clients()
    {
        await using var run = await StartAsync(shieldEnabled: true);
        await run.AdvanceAsync(seconds: 40);

        var polls = await run.CountPollsAsync(seconds: 60);

        Assert.InRange(polls, 58, 61);
    }

    [Fact]
    public async Task A_client_request_restores_one_second_polling_at_once()
    {
        await using var run = await StartAsync(shieldEnabled: false);
        await run.AdvanceAsync(seconds: 45);
        var before = run.Polls;

        run.Activity.Touch();
        await run.SettleAsync();
        Assert.True(run.Polls > before, "the request should wake the loop without waiting for the clock");

        Assert.InRange(await run.CountPollsAsync(seconds: 20), 19, 21);
    }

    private async Task<Run> StartAsync(bool shieldEnabled)
    {
        var time = new ManualTime();
        var history = new HistoryStore(Path.Combine(_directory, "axiom.db"));
        await history.InitializeAsync(CancellationToken.None);
        var settings = new ProtectionSettingsStore(Path.Combine(_directory, "protection.json"));
        Assert.True(settings.Save(new ProtectionSettings { Enabled = shieldEnabled }));
        var source = new CountingSource();
        var activity = new ClientActivity(time);
        var worker = new MonitoringWorker(
            source,
            new ConnectionSnapshotCache(),
            new FirewallRuleCoordinator(
                new FakeFirewallPolicyAdapter(), history, NullLogger<FirewallRuleCoordinator>.Instance),
            NullLogger<MonitoringWorker>.Instance,
            activity,
            settings,
            time);
        await worker.StartAsync(CancellationToken.None);
        var run = new Run(worker, source, activity, time);
        await run.SettleAsync();
        return run;
    }

    private sealed class Run(MonitoringWorker worker, CountingSource source, ClientActivity activity, ManualTime time)
        : IAsyncDisposable
    {
        public ClientActivity Activity => activity;

        public int Polls => source.Polls;

        public async Task AdvanceAsync(int seconds)
        {
            for (var i = 0; i < seconds; i++)
            {
                time.Advance(TimeSpan.FromSeconds(1));
                await SettleAsync();
            }
        }

        public async Task<int> CountPollsAsync(int seconds)
        {
            var before = Polls;
            await AdvanceAsync(seconds);
            return Polls - before;
        }

        /// <summary>Waits until the loop is waiting on the clock again.</summary>
        public async Task SettleAsync()
        {
            var quiet = 0;
            var last = -1;
            while (quiet < 3)
            {
                await Task.Delay(5);
                quiet = Polls == last && time.PendingTimers > 0 ? quiet + 1 : 0;
                last = Polls;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await worker.StopAsync(CancellationToken.None);
            worker.Dispose();
        }
    }

    private sealed class CountingSource : IConnectionSnapshotSource
    {
        private int _polls;

        public int Polls => Volatile.Read(ref _polls);

        public string Name => "counting";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _polls);
            return Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UnixEpoch,
                Connections = [],
                ProcessCount = 0,
                SourceName = Name,
            });
        }
    }

    private sealed class ManualTime : TimeProvider
    {
        private readonly object _gate = new();
        private readonly List<ManualTimer> _timers = [];
        private DateTimeOffset _now = new(2026, 11, 26, 0, 0, 0, TimeSpan.Zero);

        public int PendingTimers
        {
            get
            {
                lock (_gate)
                {
                    return _timers.Count(timer => timer.Due is not null);
                }
            }
        }

        public override DateTimeOffset GetUtcNow()
        {
            lock (_gate)
            {
                return _now;
            }
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(this, callback, state);
            lock (_gate)
            {
                _timers.Add(timer);
            }

            timer.Change(dueTime, period);
            return timer;
        }

        public void Advance(TimeSpan by)
        {
            List<ManualTimer> due;
            lock (_gate)
            {
                _now += by;
                due = _timers.Where(timer => timer.Due <= _now).ToList();
                due.ForEach(timer => timer.Due = null);
            }

            due.ForEach(timer => timer.Fire());
        }

        private sealed class ManualTimer(ManualTime owner, TimerCallback callback, object? state) : ITimer
        {
            public DateTimeOffset? Due { get; set; }

            public void Fire() => callback(state);

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (owner._gate)
                {
                    Due = dueTime == Timeout.InfiniteTimeSpan ? null : owner._now + dueTime;
                }

                return true;
            }

            public void Dispose()
            {
                lock (owner._gate)
                {
                    owner._timers.Remove(this);
                }
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }
}
