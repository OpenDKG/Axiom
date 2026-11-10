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

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    /// <summary>
    /// Stopping the service kills the resolver. Restore any adapter (macOS: network service) that
    /// still points at it so the machine regains DNS without the user having to run an elevated command.
    /// </summary>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        dnsPlatform.RestoreIfNeeded();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
