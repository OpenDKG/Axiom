// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Monitoring;
using Axiom.Core.Protection;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Polls the platform connection source (IP Helper owner tables on Windows, AxiomFilter flow
/// events or libproc on macOS) once per interval and publishes the latest snapshot.
/// </summary>
public sealed partial class MonitoringWorker(
    IConnectionSnapshotSource source,
    ConnectionSnapshotCache cache,
    FirewallRuleCoordinator firewall,
    ILogger<MonitoringWorker> logger,
    ClientActivity clients,
    ProtectionSettingsStore protection,
    TimeProvider? time = null) : BackgroundService
{
    private static readonly TimeSpan IdleAfter = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan IdleInterval = TimeSpan.FromSeconds(10);

    private readonly TimeProvider _time = time ?? TimeProvider.System;

    private static readonly TimeSpan RuleCacheLifetime = TimeSpan.FromSeconds(10);

    private IReadOnlyList<ManagedRule> _rules = [];
    private DateTimeOffset _rulesUtc = DateTimeOffset.MinValue;
    private bool _rulesAvailable;

    private readonly AppTrafficAccumulator _traffic = new();

    [LoggerMessage(EventId = 1001, Level = LogLevel.Information, Message = "Monitoring source: {Source}, interval {Interval}")]
    private static partial void LogSource(ILogger logger, string source, TimeSpan interval);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Warning, Message = "Snapshot capture failed")]
    private static partial void LogCaptureFailure(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Warning, Message = "Owned firewall rule evaluation unavailable")]
    private static partial void LogRuleFailure(ILogger logger, Exception exception);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        cache.SourceName = source.Name;
        cache.PollInterval = source.PollInterval;

        LogSource(logger, source.Name, source.PollInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var snapshot = await source.CaptureAsync(stoppingToken).ConfigureAwait(false);
                snapshot = await ApplyOwnedRulesAsync(snapshot, stoppingToken).ConfigureAwait(false);
                snapshot = _traffic.Apply(snapshot, DateTimeOffset.UtcNow);
                cache.Update(snapshot);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
#pragma warning disable CA1031 // A transient OS error must not stop the service loop.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                cache.Fail(exception.Message);
                LogCaptureFailure(logger, exception);
            }

            await WaitForNextPollAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// One poll interval, or ten seconds when no client has asked for anything for thirty seconds.
    /// Never slowed while Axiom Shield is on: it finds new applications in these snapshots. A
    /// request ends the long wait at once.
    /// </summary>
    private async Task WaitForNextPollAsync(CancellationToken cancellationToken)
    {
        var nextRequest = clients.NextRequest;
        if (clients.IsIdle(IdleAfter) && !protection.Load().Enabled && IdleInterval > source.PollInterval)
        {
            using var wake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            await Task.WhenAny(Task.Delay(IdleInterval, _time, wake.Token), nextRequest).ConfigureAwait(false);
            await wake.CancelAsync().ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return;
        }

        await Task.Delay(source.PollInterval, _time, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ConnectionSnapshot> ApplyOwnedRulesAsync(
        ConnectionSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _rulesUtc >= RuleCacheLifetime)
        {
            try
            {
                _rules = await firewall.ListAsync(cancellationToken).ConfigureAwait(false);
                _rulesUtc = now;
                _rulesAvailable = true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
#pragma warning disable CA1031 // A rule-store failure must not stop monitoring.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                _rulesAvailable = false;
                LogRuleFailure(logger, exception);
            }
        }

        if (!_rulesAvailable)
        {
            return snapshot;
        }

        var connections = snapshot.Connections
            .Select(connection => connection with
            {
                RuleStatus = OwnedRuleMatcher.Evaluate(_rules, connection),
            })
            .ToArray();

        return snapshot with { Connections = connections };
    }
}
