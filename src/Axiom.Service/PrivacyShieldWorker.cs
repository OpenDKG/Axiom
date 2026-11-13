// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Service.Hosting.Dns;
using Microsoft.Extensions.Hosting;

namespace Axiom.Service;

/// <summary>Starts the opt-in resolver with the service and stops it on shutdown.</summary>
public sealed class PrivacyShieldWorker(
    PrivacyShieldController controller,
    IPrivacyDnsPlatform dnsPlatform) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!controller.IsEnabled)
        {
            // A previous disable may have left an adapter pointed at 127.0.0.1. Restore DNS before
            // doing anything else so starting the service fixes a broken network instead of hiding it.
            dnsPlatform.RestoreIfNeeded();
        }

        await controller.StartAsync(stoppingToken).ConfigureAwait(false);
        controller.EnsureConfiguredAdapterDns();

        // Catch up any newly added or stale blocklist sources right after startup, then check hourly
        // against each source's 24h (or configured) age without blocking pipe responsiveness.
        _ = RunAutoSourceUpdaterAsync(stoppingToken);

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task RunAutoSourceUpdaterAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken).ConfigureAwait(false);
            await TryUpdateMissingOrStaleSourcesAsync(stoppingToken).ConfigureAwait(false);

            using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await TryUpdateMissingOrStaleSourcesAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task TryUpdateMissingOrStaleSourcesAsync(CancellationToken stoppingToken)
    {
        if (!controller.ShouldAutoUpdateSources())
        {
            return;
        }

        try
        {
            await controller.UpdateSourcesAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // Keep running on cached rules; the controller status retains the per-source error.
        }
    }

    /// <summary>
    /// Stopping the service kills the resolver. Restore any adapter (macOS: network service) that
    /// still points at it so the machine regains DNS without the user having to run an elevated command.
    /// </summary>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        controller.FlushBlockedHistory();
        dnsPlatform.RestoreIfNeeded();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
