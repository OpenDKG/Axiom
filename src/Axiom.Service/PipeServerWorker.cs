// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Core.Firewall;
using Axiom.Core.Platform;
using Axiom.Persistence;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>Hosts the local IPC endpoint through the platform transport. No HTTP port, no remote clients, no exec command.</summary>
public sealed partial class PipeServerWorker(
    ConnectionSnapshotCache cache,
    HistoryStore history,
    IFirewallPolicyAdapter firewall,
    FirewallRuleCoordinator coordinator,
    PrivacyShieldController privacyShield,
    IServicePlatform platform,
    ILogger<PipeServerWorker> logger) : BackgroundService
{
    [LoggerMessage(EventId = 2001, Level = LogLevel.Information, Message = "IPC endpoint ready for actor {Actor} on {Platform}")]
    private static partial void LogEndpoint(ILogger logger, string actor, string platform);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Information, Message = "{Message}")]
    private static partial void LogMessage(ILogger logger, string message);

    [LoggerMessage(EventId = 2003, Level = LogLevel.Warning, Message = "Firewall rule restore failed")]
    private static partial void LogRestoreFailure(ILogger logger, Exception exception);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var actor = platform.ResolveActorId();
        LogEndpoint(logger, actor, platform.Name);

        // The Linux eBPF policy lives in this process; re-apply audited rules after a restart when
        // enforcement is enabled. Failure leaves the audit store untouched and is reported by the
        // adapter's capability/verify results.
        if (firewall is IFirewallPolicyRestorer restorer && platform.FirewallWritesEnabled)
        {
            try
            {
                var stored = await history.ListFirewallRulesAsync(stoppingToken).ConfigureAwait(false);
                var applied = stored
                    .Where(rule => rule.State == Contracts.Firewall.RuleState.Applied)
                    .Select(rule => rule.Spec)
                    .ToArray();
                await restorer.RestoreAsync(applied, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // Enforcement must never prevent the service from starting; the audit store and
                // the adapter's verify result remain the source of truth.
                LogRestoreFailure(logger, exception);
            }
        }

        var processor = new IpcRequestProcessor(
            () => cache.Latest,
            () => CreateHealth(cache),
            (query, cancellationToken) => history.QueryAsync(query, cancellationToken),
            async cancellationToken =>
            {
                var capability = await firewall.GetCapabilitiesAsync(cancellationToken).ConfigureAwait(false);
                IReadOnlyList<Contracts.Firewall.ManagedRule> rules = capability.Status == Contracts.Firewall.FirewallCapabilityStatus.Available
                    ? await firewall.ListOwnedRulesAsync(cancellationToken).ConfigureAwait(false)
                    : [];

                return new FirewallRulesSnapshot
                {
                    Capability = capability,
                    Rules = rules,
                    WritesEnabled = platform.FirewallWritesEnabled,
                };
            },
            (spec, actorId, cancellationToken) => coordinator.ApplyAsync(spec, actorId, cancellationToken),
            (managedRuleId, actorId, cancellationToken) => coordinator.RemoveAsync(managedRuleId, actorId, cancellationToken),
            (managedRuleId, cancellationToken) => coordinator.VerifyAsync(managedRuleId, cancellationToken),
            (cancellationToken) => privacyShield.GetStatusAsync(cancellationToken),
            (settings, cancellationToken) => privacyShield.ConfigureAsync(settings, cancellationToken),
            (cancellationToken) => privacyShield.UpdateSourcesAsync(cancellationToken),
            (cancellationToken) => privacyShield.ClearHistoryAsync(cancellationToken),
            () => platform.FirewallWritesEnabled,
            message => LogMessage(logger, message));

        await platform.RunIpcServerAsync(processor, actor, stoppingToken).ConfigureAwait(false);
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
