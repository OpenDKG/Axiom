// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux.Firewall;
using Axiom.Infrastructure.Linux.Nft;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Linux: runs the nftables engine for the daemon's lifetime (docs/LINUX_ENFORCEMENT.md §6):
/// publish owned rules at start, 1 s attribution loop, ruleset watcher, <c>nft monitor trace</c>,
/// teardown (table, cgroups, herded processes returned) on stop.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
internal sealed partial class NftEnforcementWorker(
    NftFirewallPolicyAdapter firewall,
    FilterEventPipe events,
    ILogger<NftEnforcementWorker> logger) : BackgroundService
{
    [LoggerMessage(EventId = 2201, Level = LogLevel.Information, Message = "{Message}")]
    private static partial void LogMessage(ILogger logger, string message);

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsLinux())
        {
            return Task.CompletedTask;
        }

        var supervisor = LinuxEnforcement.CreateSupervisor(firewall, events, message => LogMessage(logger, message));
        return supervisor.RunAsync(stoppingToken);
    }
}
