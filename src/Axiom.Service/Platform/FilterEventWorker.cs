// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.Unix.Filter;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// macOS: republishes the AxiomFilter rule table at start (so the filter always finds the
/// daemon's current owned rules) and runs the flow-event socket the filter connects to.
/// </summary>
internal sealed partial class FilterEventWorker(
    FilterEventServer server,
    MacFirewallPolicyAdapter firewall,
    ILogger<FilterEventWorker> logger) : BackgroundService
{
    [LoggerMessage(EventId = 2101, Level = LogLevel.Information, Message = "{Message}")]
    private static partial void LogMessage(ILogger logger, string message);

    [LoggerMessage(EventId = 2102, Level = LogLevel.Information, Message = "Published AxiomFilter rules generation {Generation}.")]
    private static partial void LogPublished(ILogger logger, long generation);

    [LoggerMessage(EventId = 2103, Level = LogLevel.Warning, Message = "Could not publish AxiomFilter rules: {Error}")]
    private static partial void LogPublishFailed(ILogger logger, string error);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var generation = await firewall.PublishAsync(stoppingToken).ConfigureAwait(false);
            LogPublished(logger, generation);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            LogPublishFailed(logger, exception.Message);
        }

        // Every (re)connect of the extension gets a fresh generation, so its acknowledgement is
        // for this connection: a hello that merely repeats an old generation never counts.
        server.ClientConnectedAsync = async cancellationToken =>
        {
            var republished = await firewall.PublishAsync(cancellationToken).ConfigureAwait(false);
            LogPublished(logger, republished);
        };

        await server.RunAsync(message => LogMessage(logger, message), stoppingToken).ConfigureAwait(false);
    }
}
