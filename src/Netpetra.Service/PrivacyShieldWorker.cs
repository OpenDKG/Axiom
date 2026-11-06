// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Extensions.Hosting;

namespace Netpetra.Service;

/// <summary>Starts the opt-in resolver with the service and stops it on shutdown.</summary>
public sealed class PrivacyShieldWorker(PrivacyShieldController controller) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await controller.StartAsync(stoppingToken).ConfigureAwait(false);

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }
}
