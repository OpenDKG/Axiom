// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Infrastructure.Windows.Ipc;
using Axiom.Persistence;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>Hosts the local Named Pipe endpoint. No HTTP port, no remote clients, no exec command.</summary>
public sealed partial class PipeServerWorker(
    ConnectionSnapshotCache cache,
    HistoryStore history,
    WindowsFirewallPolicyAdapter firewall,
    FirewallRuleCoordinator coordinator,
    PrivacyShieldController privacyShield,
    ProtectionController protection,
    ThreatShareController threatShare,
    NetworkRecoveryController networkRecovery,
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
            historyQuery: (query, cancellationToken) => history.QueryAsync(query, cancellationToken),
            throughputHistory: (query, cancellationToken) =>
                history.QueryThroughputAsync(query, cancellationToken),
            rulesQuery: async cancellationToken =>
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
            ruleApply: (spec, actorSid, cancellationToken) =>
                coordinator.ApplyAsync(spec, actorSid, cancellationToken),
            ruleRemove: (managedRuleId, actorSid, cancellationToken) =>
                coordinator.RemoveAsync(managedRuleId, actorSid, cancellationToken),
            ruleVerify: (managedRuleId, cancellationToken) =>
                coordinator.VerifyAsync(managedRuleId, cancellationToken),
            privacyStatus: cancellationToken => privacyShield.GetStatusAsync(cancellationToken),
            privacyConfigure: (settings, cancellationToken) =>
                privacyShield.ConfigureAsync(settings, cancellationToken),
            privacySourcesUpdate: cancellationToken => privacyShield.UpdateSourcesAsync(cancellationToken),
            privacyHistoryClear: cancellationToken => privacyShield.ClearHistoryAsync(cancellationToken),
            protectionStatus: cancellationToken => protection.GetStatusAsync(null, cancellationToken),
            protectionEnable: (request, actorSid, cancellationToken) =>
                protection.EnableAsync(request.DefaultPolicy, actorSid, cancellationToken),
            protectionDisable: (actorSid, cancellationToken) =>
                protection.DisableAsync(actorSid, cancellationToken),
            protectionDecide: (request, actorSid, cancellationToken) =>
                protection.DecideAsync(request, actorSid, cancellationToken),
            protectionDismiss: (request, cancellationToken) =>
                protection.DismissAsync(request, cancellationToken),
            protectionLockdown: (request, actorSid, cancellationToken) =>
                protection.SetAgentLockdownAsync(request.Enabled, actorSid, cancellationToken),
            threatShareStatus: cancellationToken => threatShare.GetStatusAsync(cancellationToken),
            threatShareEnqueue: async (request, cancellationToken) =>
            {
                threatShare.Enqueue(request);
                return await threatShare.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            },
            threatShareDismiss: (request, cancellationToken) =>
                threatShare.DismissAsync(request.Id, cancellationToken),
            threatShareRecord: (request, cancellationToken) =>
                threatShare.RecordAsync(request, cancellationToken),
            networkRecoveryCapture: (actorSid, cancellationToken) =>
                networkRecovery.CaptureAsync(actorSid, cancellationToken),
            networkRecoveryRestore: (actorSid, cancellationToken) =>
                networkRecovery.RestoreAsync(actorSid, cancellationToken),
            log: message => LogMessage(logger, message));

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
