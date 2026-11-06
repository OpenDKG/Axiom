// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Firewall;
using Netpetra.Contracts.Ipc;
using Netpetra.Infrastructure.Windows.Firewall;
using Netpetra.Infrastructure.Windows.Ipc;
using Netpetra.Persistence;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Netpetra.Service;

/// <summary>Hosts the local Named Pipe endpoint. No HTTP port, no remote clients, no exec command.</summary>
public sealed partial class PipeServerWorker(
    ConnectionSnapshotCache cache,
    HistoryStore history,
    WindowsFirewallPolicyAdapter firewall,
    FirewallRuleCoordinator coordinator,
    PrivacyShieldController privacyShield,
    ILogger<PipeServerWorker> logger) : BackgroundService
{
    [LoggerMessage(EventId = 2001, Level = LogLevel.Information, Message = "Pipe {Pipe} allows SID {Sid}")]
    private static partial void LogPipe(ILogger logger, string pipe, string sid);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Information, Message = "{Message}")]
    private static partial void LogMessage(ILogger logger, string message);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var allowedSid = ServiceInfo.ResolveAllowedSid();
        LogPipe(logger, IpcPipe.Name, allowedSid);

        var server = new PipeServer(
            IpcPipe.Name,
            allowedSid,
            () => cache.Latest,
            () => CreateHealth(cache),
            (query, cancellationToken) => history.QueryAsync(query, cancellationToken),
            async cancellationToken =>
            {
                var capability = await firewall.GetCapabilitiesAsync(cancellationToken).ConfigureAwait(false);
                IReadOnlyList<ManagedRule> rules = capability.Status == FirewallCapabilityStatus.Available
                    ? await firewall.ListOwnedRulesAsync(cancellationToken).ConfigureAwait(false)
                    : [];

                return new FirewallRulesSnapshot
                {
                    Capability = capability,
                    Rules = rules,
                    WritesEnabled = WindowsFirewallPolicyAdapter.IsWriteGateOpen,
                };
            },
            (spec, actorSid, cancellationToken) => coordinator.ApplyAsync(spec, actorSid, cancellationToken),
            (managedRuleId, actorSid, cancellationToken) => coordinator.RemoveAsync(managedRuleId, actorSid, cancellationToken),
            (managedRuleId, cancellationToken) => coordinator.VerifyAsync(managedRuleId, cancellationToken),
            (cancellationToken) => privacyShield.GetStatusAsync(cancellationToken),
            (settings, cancellationToken) => privacyShield.ConfigureAsync(settings, cancellationToken),
            (cancellationToken) => privacyShield.UpdateSourcesAsync(cancellationToken),
            (cancellationToken) => privacyShield.ClearHistoryAsync(cancellationToken),
            message => LogMessage(logger, message));

        await server.RunAsync(stoppingToken).ConfigureAwait(false);
    }

    private static ServiceHealth CreateHealth(ConnectionSnapshotCache cache) => new()
    {
        Status = "running",
        UptimeSeconds = (long)(DateTimeOffset.UtcNow - ServiceInfo.StartedUtc).TotalSeconds,
        SourceName = cache.SourceName,
        PollIntervalSeconds = cache.PollInterval.TotalSeconds,
        LastCaptureUtc = cache.Latest?.CapturedUtc,
        ConnectionCount = cache.Latest?.Connections.Count ?? 0,
        ProcessCount = cache.Latest?.ProcessCount ?? 0,
        Limitations = cache.Latest?.Limitations ?? [],
        LastError = cache.LastError,
    };
}
