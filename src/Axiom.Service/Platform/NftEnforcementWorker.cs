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
    Axiom.Infrastructure.Linux.Bpf.BpfEngine bpf,
    ILogger<NftEnforcementWorker> logger) : BackgroundService
{
    [LoggerMessage(EventId = 2201, Level = LogLevel.Information, Message = "{Message}")]
    private static partial void LogMessage(ILogger logger, string message);

    [LoggerMessage(EventId = 2202, Level = LogLevel.Critical, Message = "Enforcement supervisor failed; stopping the daemon with exit code 70 for a systemd restart.")]
    private static partial void LogSupervisorFailed(ILogger logger, Exception exception);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var supervisor = LinuxEnforcement.CreateSupervisor(firewall, events, message => LogMessage(logger, message), bpf);
        try
        {
            await supervisor.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // The supervisor already tore its state down (LNX-2). A firewall daemon without enforcement must
            // not keep running as if healthy: exit non-zero so Restart=on-failure restarts it and the next
            // start reconciles. The host stops on a faulted BackgroundService (StopHost, the default).
            Environment.ExitCode = 70; // EX_SOFTWARE
            LogSupervisorFailed(logger, exception);
            throw;
        }
    }
}
