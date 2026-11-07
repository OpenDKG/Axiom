// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Axiom.Infrastructure.Windows.Firewall;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Keeps runtime consent in sync with the persisted shield state and re-applies the agent lockdown
/// when a new agent executable starts. It never turns protection on by itself.
/// </summary>
public sealed partial class ProtectionWorker(
    ProtectionSettingsStore store,
    ProtectionController controller,
    ILogger<ProtectionWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    [LoggerMessage(EventId = 4201, Level = LogLevel.Information, Message = "Axiom Shield consent granted: {Enabled}")]
    private static partial void LogConsent(ILogger logger, bool enabled);

    [LoggerMessage(EventId = 4202, Level = LogLevel.Information, Message = "Axiom Shield agent lockdown active: {Enabled}")]
    private static partial void LogLockdown(ILogger logger, bool enabled);

    [LoggerMessage(EventId = 4203, Level = LogLevel.Warning, Message = "Axiom Shield reconciliation failed")]
    private static partial void LogReconcileFailure(ILogger logger, Exception exception);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var lastEnabled = false;
        var lastLockdown = false;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = store.Load();

                if (settings.Enabled != lastEnabled)
                {
                    ProtectionWriteConsent.Set(settings.Enabled);
                    lastEnabled = settings.Enabled;
                    LogConsent(logger, settings.Enabled);
                }

                if (settings.Enabled && settings.AgentLockdown)
                {
                    await controller
                        .ReconcileAgentLockdownAsync("Axiom Shield", stoppingToken)
                        .ConfigureAwait(false);
                }

                if (settings.AgentLockdown != lastLockdown)
                {
                    lastLockdown = settings.AgentLockdown;
                    LogLockdown(logger, settings.AgentLockdown);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
#pragma warning disable CA1031 // The background loop must survive a single failed pass.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogReconcileFailure(logger, exception);
            }

            await Task.Delay(Interval, stoppingToken).ConfigureAwait(false);
        }
    }
}
