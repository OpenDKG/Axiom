// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>
/// Daemon-side lifecycle of the nftables engine (docs/LINUX_ENFORCEMENT.md §6), kept out of the
/// hosting layer so it is testable with the fake nft runner and cgroup fs:
/// reconcile orphaned Axiom-owned state from a previous daemon, publish the owned rules at start;
/// every <see cref="AttributionInterval"/> herd matching processes into their app cgroups
/// (<see cref="NftFirewallPolicyAdapter.Attribute"/>) and log the reportable placements; every
/// <see cref="WatchInterval"/> check that <c>table inet axiom</c> still holds the published
/// generation and republish when another tool flushed it (and re-attach a neutralised BPF layer);
/// keep <c>nft monitor trace</c> running (restart after exit); and on stop, cancellation <b>or an
/// unexpected loop fault</b> run every teardown step (BPF detach/unpin, table delete, cgroup
/// release) bounded and independently (PR #276 review, LNX-2).
/// </summary>
public sealed class NftEnforcementSupervisor
{
    public static readonly TimeSpan DefaultAttributionInterval = TimeSpan.FromSeconds(1);

    public static readonly TimeSpan DefaultWatchInterval = TimeSpan.FromSeconds(10);

    public static readonly TimeSpan DefaultTraceRestartDelay = TimeSpan.FromSeconds(2);

    /// <summary>Upper bound per teardown step; below systemd's <c>TimeoutStopSec=30</c> for three steps.</summary>
    public static readonly TimeSpan DefaultTeardownStepTimeout = TimeSpan.FromSeconds(8);

    private readonly NftFirewallPolicyAdapter _adapter;

    private readonly NftTable _table;

    private readonly Func<NftTraceMonitor>? _traceMonitor;

    private readonly IEnforcementLayer? _layer;

    private readonly Action<string> _log;

    private readonly TimeProvider _time;

    private long _republishes;

    private long _attributionPasses;

    private long _layerReattachments;

    public NftEnforcementSupervisor(
        NftFirewallPolicyAdapter adapter,
        NftTable table,
        Func<NftTraceMonitor>? traceMonitor,
        Action<string> log,
        TimeProvider time)
        : this(adapter, table, traceMonitor, null, log, time)
    {
    }

    /// <param name="layer">Optional connect-time layer (BPF): started after the first publish, synced from the stored rules, stopped before teardown.</param>
    public NftEnforcementSupervisor(
        NftFirewallPolicyAdapter adapter,
        NftTable table,
        Func<NftTraceMonitor>? traceMonitor,
        IEnforcementLayer? layer,
        Action<string> log,
        TimeProvider time)
    {
        _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        _table = table ?? throw new ArgumentNullException(nameof(table));
        _traceMonitor = traceMonitor;
        _layer = layer;
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public TimeSpan AttributionInterval { get; init; } = DefaultAttributionInterval;

    public TimeSpan WatchInterval { get; init; } = DefaultWatchInterval;

    public TimeSpan TraceRestartDelay { get; init; } = DefaultTraceRestartDelay;

    public TimeSpan TeardownStepTimeout { get; init; } = DefaultTeardownStepTimeout;

    /// <summary>Generation published at start (or -1 when the first publish failed).</summary>
    public long StartGeneration { get; private set; } = -1;

    /// <summary>Times the watcher found the table missing and republished it.</summary>
    public long Republishes => Interlocked.Read(ref _republishes);

    private long _degradations;

    /// <summary>Times the watcher degraded the enforcement report before republishing.</summary>
    public long Degradations => Interlocked.Read(ref _degradations);

    public long AttributionPasses => Interlocked.Read(ref _attributionPasses);

    /// <summary>Times the watcher re-attached a neutralised BPF layer.</summary>
    public long LayerReattachments => Interlocked.Read(ref _layerReattachments);

    /// <summary>What the last teardown found or failed on (empty = clean); for tests and the journal.</summary>
    public IReadOnlyList<string> TeardownErrors { get; private set; } = [];

    /// <summary>The loop fault (if any) that ended the last run; null on normal stop.</summary>
    public Exception? LastFault { get; private set; }

    /// <summary>Orphaned Axiom-owned state found at start (for tests and the journal).</summary>
    public IReadOnlyList<string> OrphansReconciled { get; private set; } = [];

    /// <summary>
    /// Publishes, runs the loops until cancelled, then tears down. Never throws on cancellation.
    /// An unexpected loop fault cancels the sibling loops, runs the full teardown, and is rethrown
    /// (systemd restarts the unit; the next start reconciles).
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        LastFault = null;
        TeardownErrors = [];
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try
        {
            await ReconcileOrphansAsync(linked.Token).ConfigureAwait(false);
            await PublishAtStartAsync(linked.Token).ConfigureAwait(false);
            await StartLayerAsync(linked.Token).ConfigureAwait(false);
            LogLimitations();

            var loops = new List<Task>
            {
                Loop(AttributionInterval, () => Task.FromResult(AttributeOnce()), linked.Token),
                Loop(WatchInterval, () => WatchOnceAsync(linked.Token), linked.Token),
            };
            if (_traceMonitor is not null)
            {
                loops.Add(RunTraceMonitorAsync(linked.Token));
            }

            if (_layer is not null)
            {
                loops.Add(_layer.RunEventsAsync(linked.Token));
            }

            await RunLoopsAsync(loops, linked).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Stopping.
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            LastFault = exception;
            _log($"Enforcement supervisor faulted: {exception.GetType().Name}: {exception.Message}; tearing down.");
            throw;
        }
        finally
        {
            await TeardownAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Waits for the loops; the first faulted loop cancels the others and its exception wins.</summary>
    private async Task RunLoopsAsync(List<Task> loops, CancellationTokenSource linked)
    {
        var pending = new List<Task>(loops);
        Exception? fault = null;
        while (pending.Count > 0)
        {
            var finished = await Task.WhenAny(pending).ConfigureAwait(false);
            pending.Remove(finished);
            if (finished.IsFaulted && fault is null && finished.Exception?.GetBaseException() is { } exception and not OperationCanceledException)
            {
                fault = exception;
                _log($"Enforcement loop faulted: {exception.GetType().Name}: {exception.Message}; stopping the other loops.");
                await linked.CancelAsync().ConfigureAwait(false);
            }
        }

        if (fault is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(fault).Throw();
        }

        if (linked.IsCancellationRequested)
        {
            throw new OperationCanceledException(linked.Token);
        }
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
    /// older generation than the one published, republish from <c>managed-rules.json</c>. Also the
    /// bounded recovery of a neutralised BPF layer: one re-attach attempt per tick.
    /// </summary>
    public async Task<bool> WatchOnceAsync(CancellationToken ct)
    {
        var republished = await WatchTableAsync(ct).ConfigureAwait(false);
        if (_layer is { Neutralised: true })
        {
            _log("BPF layer is neutralised; re-attaching and resyncing from managed-rules.json.");
            await StartLayerAsync(ct).ConfigureAwait(false);
            if (_layer.Active)
            {
                Interlocked.Increment(ref _layerReattachments);
                _log("BPF layer re-attached; enforcement " + (_adapter.Enforcement?.State.ToString().ToLowerInvariant() ?? "unknown") + ".");
            }
        }

        return republished;
    }

    private async Task<bool> WatchTableAsync(CancellationToken ct)
    {
        var expected = _adapter.Enforcement?.PublishedGeneration;
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
            // Degrade at once: nothing proves the table is enforced while nft cannot be read.
            var degraded = await _adapter.MarkTableLostAsync(ct).ConfigureAwait(false);
            _log($"Ruleset watcher: nft is unavailable ({exception.Message}); enforcement {degraded.State.ToString().ToLowerInvariant()}.");
            return false;
        }

        if (live == expected)
        {
            return false;
        }

        // The Linux counterpart of the macOS filter disconnect: degrade the report immediately,
        // then republish; the fresh readback is what makes the new generation verified again.
        var lost = await _adapter.MarkTableLostAsync(ct).ConfigureAwait(false);
        Interlocked.Increment(ref _degradations);
        _log(live is null
            ? string.Create(CultureInfo.InvariantCulture, $"table inet axiom disappeared (generation {expected} was published); enforcement {lost.State.ToString().ToLowerInvariant()}; republishing.")
            : string.Create(CultureInfo.InvariantCulture, $"table inet axiom holds generation {live}, expected {expected}; enforcement {lost.State.ToString().ToLowerInvariant()}; republishing."));
        try
        {
            var generation = await _adapter.PublishAsync(ct).ConfigureAwait(false);
            Interlocked.Increment(ref _republishes);
            var after = await _adapter.RefreshAsync(ct).ConfigureAwait(false);
            _log(string.Create(CultureInfo.InvariantCulture, $"Republished table inet axiom generation {generation}; enforcement {after.State.ToString().ToLowerInvariant()}."));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _log($"Republish failed: {exception.Message}");
            return false;
        }
    }

    /// <summary>
    /// Startup reconciliation (LNX-2): a daemon that was killed (SIGKILL, OOM, watchdog) leaves
    /// <c>table inet axiom</c>, <c>axiom.slice</c> app cgroups with herded processes, and attached/pinned
    /// BPF programs behind. The table is replaced atomically by the first publish and the BPF layer
    /// rebuilds its pins itself; here the cgroups of apps that no longer have rules are released and
    /// everything found is logged so the journal shows the recovery. Third-party tables, cgroups and
    /// programs are never listed, let alone touched.
    /// </summary>
    public async Task ReconcileOrphansAsync(CancellationToken ct)
    {
        var found = new List<string>();
        try
        {
            var live = await _table.ReadGenerationAsync(ct).ConfigureAwait(false);
            if (live is { } generation)
            {
                found.Add(string.Create(CultureInfo.InvariantCulture, $"table inet axiom generation {generation} (replaced by the first publish)"));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            found.Add($"nft unreadable ({exception.Message})");
        }

        try
        {
            var orphans = _adapter.ReconcileCgroups();
            found.AddRange(orphans);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            found.Add($"cgroup reconciliation failed ({exception.Message})");
        }

        OrphansReconciled = found;
        if (found.Count > 0)
        {
            _log("Startup reconciliation: " + string.Join("; ", found) + ".");
        }
    }

    private async Task PublishAtStartAsync(CancellationToken ct)
    {
        try
        {
            StartGeneration = await _adapter.PublishAsync(ct).ConfigureAwait(false);
            var report = await _adapter.RefreshAsync(ct).ConfigureAwait(false);
            _log(report.FileError is { Length: > 0 } error
                ? string.Create(CultureInfo.InvariantCulture, $"nftables rejected table inet axiom generation {StartGeneration}: {error}")
                : string.Create(CultureInfo.InvariantCulture, $"Published table inet axiom generation {StartGeneration} ({report.AppliedRuleCount} applied, {report.RejectedRules.Count} rejected); enforcement {report.State.ToString().ToLowerInvariant()}."));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _log($"Could not publish table inet axiom: {exception.Message}");
        }
    }

    /// <summary>Logged after the connect-time layer had its chance to attach, so the BPF line is accurate.</summary>
    private void LogLimitations()
    {
        foreach (var limitation in _adapter.Limitations())
        {
            _log("Enforcement limitation: " + limitation);
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

    /// <summary>Attaches the layer (never throws) and syncs it from the rules the first publish stored.</summary>
    public async Task StartLayerAsync(CancellationToken ct)
    {
        if (_layer is null)
        {
            return;
        }

        try
        {
            await _layer.StartAsync(ct).ConfigureAwait(false);
            if (_layer.Active)
            {
                await _adapter.ResyncLayerAsync(ct).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _log($"Connect-time layer failed to start: {exception.Message}; nftables only.");
        }
    }

    /// <summary>
    /// Best-effort, bounded teardown: every step runs even when another failed or hung
    /// (<see cref="TeardownStepTimeout"/>); errors are collected in <see cref="TeardownErrors"/> and
    /// logged after the original fault. Steps: BPF detach + unpin, <c>delete table inet axiom</c>,
    /// release herded processes + remove <c>axiom.slice</c> cgroups. Only Axiom-owned objects.
    /// </summary>
    private async Task TeardownAsync()
    {
        var errors = new List<string>();
        if (_layer is not null)
        {
            await StepAsync("BPF layer stop", () => _layer.StopAsync(), errors).ConfigureAwait(false);
        }

        await StepAsync("delete table inet axiom", () => _adapter.DeleteTableAsync(CancellationToken.None), errors).ConfigureAwait(false);
        await StepAsync("release cgroups", () => Task.Run(_adapter.ReleaseCgroups), errors).ConfigureAwait(false);
        _adapter.ForgetPublished();
        TeardownErrors = errors;
        _log(errors.Count == 0
            ? "Removed table inet axiom and the Axiom cgroups; herded processes returned."
            : $"Teardown finished with {errors.Count} error(s): {string.Join("; ", errors)}");
    }

    private async Task StepAsync(string name, Func<Task> step, List<string> errors)
    {
        try
        {
            await step().WaitAsync(TeardownStepTimeout).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            errors.Add($"{name}: timed out after {TeardownStepTimeout.TotalSeconds:0} s");
            _log($"Teardown step '{name}' timed out after {TeardownStepTimeout.TotalSeconds:0} s; continuing with the next step.");
        }
        catch (Exception exception)
        {
            errors.Add($"{name}: {exception.Message}");
            _log($"Teardown step '{name}' failed: {exception.GetType().Name}: {exception.Message}; continuing with the next step.");
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
