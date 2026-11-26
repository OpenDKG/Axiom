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
    NetworkRecoveryController networkRecovery,
    ILogger<PipeServerWorker> logger,
    ClientActivity clients,
    EnforcementController? enforcement = null) : BackgroundService
{
    // Windows logs "Pipe \\.\pipe\axiom allows SID S-1-…" (unchanged wording); macOS logs the socket
    // path and its uid policy through the same message.
    [LoggerMessage(EventId = 2001, Level = LogLevel.Information, Message = "{Kind} {Endpoint} {Verb} {Callers}")]
    private static partial void LogEndpoint(ILogger logger, string kind, string endpoint, string verb, string callers);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Information, Message = "{Message}")]
    private static partial void LogMessage(ILogger logger, string message);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var allowedCallers = transport.Prepare();
        LogEndpoint(
            logger,
            OperatingSystem.IsWindows() ? "Pipe" : "IPC endpoint",
            transport.Endpoint,
            OperatingSystem.IsWindows() ? "allows SID" : "accepts callers",
            allowedCallers);

        var handlers = new IpcRequestHandlers
        {
            SnapshotProvider = () => cache.Latest,
            ClientActivity = clients,
            HealthProvider = () => CreateHealth(cache),
            HistoryQuery = (query, cancellationToken) => history.QueryAsync(query, cancellationToken),
            ThroughputHistory = (query, cancellationToken) =>
                history.QueryThroughputAsync(query, cancellationToken),
            RulesQuery = async cancellationToken =>
            {
                var capability = await firewall.GetCapabilitiesAsync(cancellationToken).ConfigureAwait(false);
                // Degraded (macOS: filter disconnected) still lists the published rules so the UI can
                // show them as pending; Windows reports Available or Unavailable only.
                IReadOnlyList<ManagedRule> rules = capability.Status is FirewallCapabilityStatus.Available or FirewallCapabilityStatus.Degraded
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
            ThreatShareVerify = (request, cancellationToken) =>
                threatShare.VerifyAsync(request, cancellationToken),
            ThreatShareDismiss = (request, cancellationToken) =>
                threatShare.DismissAsync(request.Id, cancellationToken),
            ThreatShareRecord = (request, cancellationToken) =>
                threatShare.RecordAsync(request, cancellationToken),
            NetworkRecoveryCapture = (actorSid, cancellationToken) =>
                networkRecovery.CaptureAsync(actorSid, cancellationToken),
            NetworkRecoveryRestore = (actorSid, cancellationToken) =>
                networkRecovery.RestoreAsync(actorSid, cancellationToken),

            // Agent enforcement (#322): the controller is registered by the Windows host only
            // (ServicePlatform.ConfigureAgentEnforcement). Where it is absent the three commands
            // answer not_supported, exactly as the dispatcher does for any null handler.
            EnforcementStatus = enforcement is null
                ? null
                : cancellationToken => Task.FromResult(enforcement.GetStatus()),
            EnforcementEvaluate = enforcement is null
                ? null
                : (request, actorSid, cancellationToken) =>
                    enforcement.EvaluateAsync(request, actorSid, cancellationToken),
            EnforcementReceipts = enforcement is null
                ? null
                : cancellationToken => Task.FromResult(enforcement.GetReceipts()),
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
