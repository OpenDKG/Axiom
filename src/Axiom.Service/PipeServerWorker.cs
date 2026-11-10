// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Core.Firewall;
using Axiom.Persistence;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Hosts the local service endpoint (Windows named pipe, macOS Unix socket). No HTTP port, no
/// remote clients, no exec command. Transport and caller authentication come from
/// <see cref="IIpcTransport"/>; the command set is identical on every platform.
/// </summary>
public sealed partial class PipeServerWorker(
    IIpcTransport transport,
    ConnectionSnapshotCache cache,
    HistoryStore history,
    IFirewallPolicyAdapter firewall,
    FirewallRuleCoordinator coordinator,
    PrivacyShieldController privacyShield,
    ProtectionController protection,
    ThreatShareController threatShare,
    ILogger<PipeServerWorker> logger) : BackgroundService
{
    [LoggerMessage(EventId = 2001, Level = LogLevel.Information, Message = "Pipe {Pipe} allows SID {Sid}")]
    private static partial void LogPipe(ILogger logger, string pipe, string sid);

    [LoggerMessage(EventId = 2003, Level = LogLevel.Information, Message = "IPC endpoint {Endpoint} accepts callers {Callers}")]
    private static partial void LogEndpoint(ILogger logger, string endpoint, string callers);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Information, Message = "{Message}")]
    private static partial void LogMessage(ILogger logger, string message);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var allowedCallers = transport.Prepare();
        if (OperatingSystem.IsWindows())
        {
            LogPipe(logger, transport.Endpoint, allowedCallers);
        }
        else
        {
            LogEndpoint(logger, transport.Endpoint, allowedCallers);
        }

        var handlers = new IpcRequestHandlers
        {
            SnapshotProvider = () => cache.Latest,
            HealthProvider = () => CreateHealth(cache),
            HistoryQuery = (query, cancellationToken) => history.QueryAsync(query, cancellationToken),
            ThroughputHistory = (query, cancellationToken) =>
                history.QueryThroughputAsync(query, cancellationToken),
            RulesQuery = async cancellationToken =>
            {
                var capability = await firewall.GetCapabilitiesAsync(cancellationToken).ConfigureAwait(false);
                IReadOnlyList<ManagedRule> rules = capability.Status == FirewallCapabilityStatus.Available
                    ? await firewall.ListOwnedRulesAsync(cancellationToken).ConfigureAwait(false)
                    : [];

                return new FirewallRulesSnapshot
                {
                    Capability = capability,
                    Rules = rules,
                    WritesEnabled = FirewallWriteGate.IsOpen,
                };
            },
            RuleApply = (spec, actorSid, cancellationToken) =>
                coordinator.ApplyAsync(spec, actorSid, cancellationToken),
            RuleRemove = (managedRuleId, actorSid, cancellationToken) =>
                coordinator.RemoveAsync(managedRuleId, actorSid, cancellationToken),
            RuleVerify = (managedRuleId, cancellationToken) =>
                coordinator.VerifyAsync(managedRuleId, cancellationToken),
            PrivacyStatus = cancellationToken => privacyShield.GetStatusAsync(cancellationToken),
            PrivacyConfigure = (settings, cancellationToken) =>
                privacyShield.ConfigureAsync(settings, cancellationToken),
            PrivacySourcesUpdate = cancellationToken => privacyShield.UpdateSourcesAsync(cancellationToken),
            PrivacyHistoryClear = cancellationToken => privacyShield.ClearHistoryAsync(cancellationToken),
            ProtectionStatus = cancellationToken => protection.GetStatusAsync(null, cancellationToken),
            ProtectionEnable = (request, actorSid, cancellationToken) =>
                protection.EnableAsync(request.DefaultPolicy, actorSid, cancellationToken),
            ProtectionDisable = (actorSid, cancellationToken) =>
                protection.DisableAsync(actorSid, cancellationToken),
            ProtectionDecide = (request, actorSid, cancellationToken) =>
                protection.DecideAsync(request, actorSid, cancellationToken),
            ProtectionDismiss = (request, cancellationToken) =>
                protection.DismissAsync(request, cancellationToken),
            ProtectionLockdown = (request, actorSid, cancellationToken) =>
                protection.SetAgentLockdownAsync(request.Enabled, actorSid, cancellationToken),
            ThreatShareStatus = cancellationToken => threatShare.GetStatusAsync(cancellationToken),
            ThreatShareEnqueue = async (request, cancellationToken) =>
            {
                threatShare.Enqueue(request);
                return await threatShare.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            },
            ThreatShareDismiss = (request, cancellationToken) =>
                threatShare.DismissAsync(request.Id, cancellationToken),
            ThreatShareRecord = (request, cancellationToken) =>
                threatShare.RecordAsync(request, cancellationToken),
        };

        var dispatcher = new IpcRequestDispatcher(
            handlers,
            () => FirewallWriteGate.IsOpen,
            message => LogMessage(logger, message));

        await transport.RunAsync(dispatcher, message => LogMessage(logger, message), stoppingToken)
            .ConfigureAwait(false);
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
