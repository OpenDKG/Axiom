// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Monitoring;
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
    ILogger<MonitoringWorker> logger) : BackgroundService
{
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

        using var timer = new PeriodicTimer(source.PollInterval);

        do
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
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
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
