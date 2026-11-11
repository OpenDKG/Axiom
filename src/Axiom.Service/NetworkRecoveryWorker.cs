// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.NetworkRecovery;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Captures the machine baseline when the elevated service starts and runs the resolver-aware DNS
/// watchdog. The watchdog is driven by service state (intent plus live resolver), never by the
/// desktop lifecycle, so closing the desktop cannot roll back an intentionally active protection.
/// </summary>
public sealed partial class NetworkRecoveryWorker(
    NetworkRecoveryController controller,
    PrivacyShieldController privacyShield,
    INetworkRecoveryDnsAdapter dns,
    ILogger<NetworkRecoveryWorker> logger) : BackgroundService
{
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan RestoreCooldown = TimeSpan.FromMinutes(5);

    private bool _restartAttempted;

    private DateTimeOffset _lastRestoreUtc = DateTimeOffset.MinValue;

    [LoggerMessage(EventId = 4310, Level = LogLevel.Information,
        Message = "Network recovery baseline check finished with {Status}")]
    private static partial void LogCaptureStatus(ILogger logger, NetworkRecoveryStatus status);

    [LoggerMessage(EventId = 4311, Level = LogLevel.Warning,
        Message = "Network recovery baseline could not be captured: {Message}")]
    private static partial void LogCaptureFailure(ILogger logger, string message);

    [LoggerMessage(EventId = 4312, Level = LogLevel.Warning,
        Message = "Network watchdog is restarting the loopback resolver")]
    private static partial void LogRestartingResolver(ILogger logger);

    [LoggerMessage(EventId = 4313, Level = LogLevel.Warning,
        Message = "Network watchdog restored DNS only: {Status} ({Message})")]
    private static partial void LogWatchdogRestore(ILogger logger, NetworkRecoveryStatus status, string message);

    [LoggerMessage(EventId = 4314, Level = LogLevel.Error,
        Message = "Network watchdog probe failed: {Message}")]
    private static partial void LogProbeFailure(ILogger logger, string message);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(ProbeInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await ProbeAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    /// <summary>
    /// Capture completes before the host starts the pipe server, so an IPC-driven protection change
    /// cannot run before the baseline exists.
    /// </summary>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await CaptureBaselineAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task CaptureBaselineAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await controller.CaptureAsync("service-startup", cancellationToken).ConfigureAwait(false);
            if (result.Status is NetworkRecoveryStatus.Succeeded or NetworkRecoveryStatus.AlreadyCaptured)
            {
                LogCaptureStatus(logger, result.Status);
                return;
            }

            LogCaptureFailure(
                logger,
                string.Join(" ", result.Problems.Select(problem => problem.Message)));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
#pragma warning disable CA1031 // Capture is best-effort; a failure must not stop the service.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            LogCaptureFailure(logger, exception.Message);
        }
    }

    private async Task ProbeAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (NetworkRecoverySnapshotStore.Read(controller.SnapshotPath).Status !=
                NetworkRecoverySnapshotReadStatus.Valid)
            {
                _restartAttempted = false;
                return;
            }

            var action = NetworkWatchdog.Decide(
                privacyShield.IsEnabled,
                privacyShield.IsResolverRunning,
                dns.AnyAdapterUsesLoopbackDns(),
                _restartAttempted);

            switch (action)
            {
                case NetworkWatchdogAction.RestartResolver:
                    _restartAttempted = true;
                    LogRestartingResolver(logger);
                    try
                    {
                        await privacyShield.StartAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is
                                 InvalidOperationException or UnauthorizedAccessException or IOException)
                    {
                        LogProbeFailure(logger, exception.Message);
                    }

                    break;

                case NetworkWatchdogAction.RestoreDns:
                    var now = DateTimeOffset.UtcNow;
                    if (now - _lastRestoreUtc < RestoreCooldown)
                    {
                        return;
                    }

                    _lastRestoreUtc = now;
                    _restartAttempted = false;
                    var result = await controller
                        .RestoreDnsOnlyAsync("service-watchdog", cancellationToken)
                        .ConfigureAwait(false);
                    LogWatchdogRestore(
                        logger,
                        result.Status,
                        string.Join(" ", result.Problems.Select(problem => problem.Message)));
                    break;

                default:
                    _restartAttempted = false;
                    break;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
#pragma warning disable CA1031 // The watchdog is a service boundary; a probe must never stop the host.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            LogProbeFailure(logger, exception.Message);
        }
    }
}
