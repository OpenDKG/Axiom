// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Persists indicators observed on the DNS path into the durable preview queue. Submission is the
/// desktop's job: only the signed-in user's session holds the Blackbox reporter and DKG identity.
/// </summary>
public sealed partial class ThreatShareWorker(
    ThreatShareController controller,
    ILogger<ThreatShareWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    [LoggerMessage(EventId = 5101, Level = LogLevel.Warning, Message = "Threat share queue flush failed")]
    private static partial void LogFailure(ILogger logger, Exception exception);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await controller.FlushAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
#pragma warning disable CA1031 // One failed flush must not stop the queue from draining.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogFailure(logger, exception);
            }
        }
    }
}
