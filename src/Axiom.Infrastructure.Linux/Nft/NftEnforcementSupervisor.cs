// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>
/// Daemon-side lifecycle of the nftables engine (docs/LINUX_ENFORCEMENT.md §6), kept out of the
/// hosting layer so it is testable with the fake nft runner and cgroup fs:
/// publish the owned rules at start; every <see cref="AttributionInterval"/> herd matching
/// processes into their app cgroups (<see cref="NftFirewallPolicyAdapter.Attribute"/>) and log the
/// reportable placements; every <see cref="WatchInterval"/> check that <c>table inet axiom</c> still
/// holds the published generation and republish when another tool flushed it; keep
/// <c>nft monitor trace</c> running (restart after exit); and on cancellation tear the table and the
/// cgroups down, returning herded processes.
/// </summary>
public sealed class NftEnforcementSupervisor
{
    public static readonly TimeSpan DefaultAttributionInterval = TimeSpan.FromSeconds(1);

    public static readonly TimeSpan DefaultWatchInterval = TimeSpan.FromSeconds(10);

    public static readonly TimeSpan DefaultTraceRestartDelay = TimeSpan.FromSeconds(2);

    private readonly NftFirewallPolicyAdapter _adapter;

    private readonly NftTable _table;

    private readonly Func<NftTraceMonitor>? _traceMonitor;

    private readonly Action<string> _log;

    private readonly TimeProvider _time;

    private long _republishes;

    private long _attributionPasses;

    public NftEnforcementSupervisor(
        NftFirewallPolicyAdapter adapter,
        NftTable table,
        Func<NftTraceMonitor>? traceMonitor,
        Action<string> log,
        TimeProvider time)
    {
        _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        _table = table ?? throw new ArgumentNullException(nameof(table));
        _traceMonitor = traceMonitor;
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public TimeSpan AttributionInterval { get; init; } = DefaultAttributionInterval;

    public TimeSpan WatchInterval { get; init; } = DefaultWatchInterval;

    public TimeSpan TraceRestartDelay { get; init; } = DefaultTraceRestartDelay;

    /// <summary>Generation published at start (or -1 when the first publish failed).</summary>
    public long StartGeneration { get; private set; } = -1;

    /// <summary>Times the watcher found the table missing and republished it.</summary>
    public long Republishes => Interlocked.Read(ref _republishes);

    public long AttributionPasses => Interlocked.Read(ref _attributionPasses);

    /// <summary>Publishes, runs the loops until cancelled, then tears down. Never throws on cancellation.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        await PublishAtStartAsync(ct).ConfigureAwait(false);

        var loops = new List<Task>
        {
            Loop(AttributionInterval, () => Task.FromResult(AttributeOnce()), ct),
            Loop(WatchInterval, () => WatchOnceAsync(ct), ct),
        };
        if (_traceMonitor is not null)
        {
            loops.Add(RunTraceMonitorAsync(ct));
        }

        try
        {
            await Task.WhenAll(loops).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }

        await TeardownAsync().ConfigureAwait(false);
    }

    /// <summary>One attribution pass; reportable placements (system-service moves, failures) are logged.</summary>
    public bool AttributeOnce()
    {
        try
        {
            var report = _adapter.Attribute();
            Interlocked.Increment(ref _attributionPasses);
            foreach (var placement in report.Placements.Where(placement => placement.Reportable))
            {
                _log("Attribution: " + AppCgroupManager.Describe(placement));
            }

            foreach (var removed in report.RemovedCgroups)
            {
                _log($"Attribution: removed unused cgroup {removed}.");
            }

            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _log($"Attribution pass failed: {exception.Message}");
            return false;
        }
    }

    /// <summary>
    /// The ruleset watcher: when the table is gone (someone ran <c>nft flush ruleset</c>) or holds an
    /// older generation than the one published, republish from <c>managed-rules.json</c>.
    /// </summary>
    public async Task<bool> WatchOnceAsync(CancellationToken ct)
    {
        var expected = _adapter.Enforcement?.Generation;
        if (expected is null || expected < 0)
        {
            return false;
        }

        long? live;
        try
        {
            live = await _table.ReadGenerationAsync(ct).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _log($"Ruleset watcher: nft is unavailable ({exception.Message}).");
            return false;
        }

        if (live == expected)
        {
            return false;
        }

        _log(live is null
            ? string.Create(CultureInfo.InvariantCulture, $"table inet axiom disappeared (generation {expected} was published); republishing.")
            : string.Create(CultureInfo.InvariantCulture, $"table inet axiom holds generation {live}, expected {expected}; republishing."));
        try
        {
            var generation = await _adapter.PublishAsync(ct).ConfigureAwait(false);
            Interlocked.Increment(ref _republishes);
            _log(string.Create(CultureInfo.InvariantCulture, $"Republished table inet axiom generation {generation}."));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _log($"Republish failed: {exception.Message}");
            return false;
        }
    }

    private async Task PublishAtStartAsync(CancellationToken ct)
    {
        try
        {
            StartGeneration = await _adapter.PublishAsync(ct).ConfigureAwait(false);
            var report = _adapter.Enforcement;
            _log(report?.FileError is { Length: > 0 } error
                ? string.Create(CultureInfo.InvariantCulture, $"nftables rejected table inet axiom generation {StartGeneration}: {error}")
                : string.Create(CultureInfo.InvariantCulture, $"Published table inet axiom generation {StartGeneration} ({report?.AppliedRuleCount ?? 0} applied, {report?.RejectedRules.Count ?? 0} rejected)."));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _log($"Could not publish table inet axiom: {exception.Message}");
        }
    }

    private async Task RunTraceMonitorAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var monitor = _traceMonitor!();
                await monitor.RunAsync(ct).ConfigureAwait(false);
                _log("nft monitor trace exited; restarting.");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                _log($"nft monitor trace failed: {exception.Message}; restarting.");
            }

            await Task.Delay(TraceRestartDelay, _time, ct).ConfigureAwait(false);
        }
    }

    private async Task TeardownAsync()
    {
        try
        {
            await _adapter.TeardownAsync(CancellationToken.None).ConfigureAwait(false);
            _log("Removed table inet axiom and the Axiom cgroups; herded processes returned.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _log($"Teardown failed: {exception.Message}");
        }
    }

    private async Task Loop(TimeSpan interval, Func<Task> body, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(interval, _time, ct).ConfigureAwait(false);
            await body().ConfigureAwait(false);
        }
    }
}
