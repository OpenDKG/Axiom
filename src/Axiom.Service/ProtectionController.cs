// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Principal;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Protection;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Axiom Shield: persisted consent, the ask policy and the owned-rule decisions. All writes go
/// through <see cref="FirewallRuleCoordinator"/> so every change is validated, applied, read back
/// and audited. Nothing is deleted unless it carries an Axiom rule name.
/// </summary>
public sealed partial class ProtectionController(
    ProtectionSettingsStore store,
    ConnectionSnapshotCache snapshots,
    FirewallRuleCoordinator coordinator,
    ILogger<ProtectionController> logger)
{
    public ProtectionSettings Settings => store.Load();

    [LoggerMessage(EventId = 4101, Level = LogLevel.Warning, Message = "Axiom Shield rule apply failed for {Path}")]
    private static partial void LogRuleFailure(ILogger logger, string path, Exception exception);

    [LoggerMessage(EventId = 4102, Level = LogLevel.Information, Message = "Axiom Shield enabled by {Actor}; policy {Policy}")]
    private static partial void LogEnabled(ILogger logger, string actor, string policy);

    [LoggerMessage(EventId = 4103, Level = LogLevel.Information, Message = "Axiom Shield disabled by {Actor}; {Failures} rule(s) could not be removed")]
    private static partial void LogDisabled(ILogger logger, string actor, int failures);

    public async Task<ProtectionStatus> GetStatusAsync(string? error, CancellationToken cancellationToken)
    {
        var settings = store.Load();
        var decisions = settings.Decisions ?? [];
        var connections = snapshots.Latest?.Connections ?? [];
        var rules = await coordinator.ListAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var detected = settings.Enabled
            ? PendingAppDetector.Detect(connections, decisions, now: now)
            : [];
        var queue = settings.Enabled
            ? PendingAppLedger.Merge(settings.Pending, settings.Dismissals, detected, decisions, now)
            : new PendingQueueResult([], [], false);

        if (settings.Enabled && queue.Changed)
        {
            _ = store.Save(settings with
            {
                Pending = queue.Pending,
                Dismissals = queue.Dismissals,
            });
        }

        return new ProtectionStatus
        {
            Enabled = settings.Enabled,
            ServiceElevated = ProtectionWriteConsent.IsServiceHost,
            WriteGateOpen = FirewallWriteGate.IsOpen,
            AccountName = CurrentAccount(),
            DefaultPolicy = settings.DefaultPolicy,
            Pending = queue.Pending,
            Decisions = decisions,
            AgentPaths = connections
                .Select(connection => connection.AppPath)
                .Where(path => AgentExecutables.IsAgentPath(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            AgentLockdown = settings.AgentLockdown,
            OwnedRuleCount = rules.Count,
            LastError = error,
        };
    }

    public async Task<ProtectionStatus> EnableAsync(string defaultPolicy, string actor, CancellationToken cancellationToken)
    {
        if (!ProtectionWriteConsent.IsServiceHost)
        {
            return await GetStatusAsync(
                OperatingSystem.IsWindows()
                    ? "Axiom Shield needs the Axiom Windows service. Approve the administrator prompt to install it."
                    : "Axiom Shield needs the axiomd system daemon. Install it with administrator rights.",
                cancellationToken).ConfigureAwait(false);
        }

        var settings = store.Load() with
        {
            Enabled = true,
            DefaultPolicy = string.IsNullOrWhiteSpace(defaultPolicy) ? "ask" : defaultPolicy,
            EnabledUtc = DateTimeOffset.UtcNow,
        };

        if (!store.Save(settings))
        {
            return await GetStatusAsync(
                $"Shield state could not be written to {store.FilePath}.",
                cancellationToken).ConfigureAwait(false);
        }

        ProtectionWriteConsent.Set(true);
        LogEnabled(logger, actor, settings.DefaultPolicy);
        return await GetStatusAsync(null, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProtectionStatus> DisableAsync(string actor, CancellationToken cancellationToken)
    {
        var settings = store.Load();
        var failures = 0;

        foreach (var rule in await coordinator.ListAsync(cancellationToken).ConfigureAwait(false))
        {
            var removed = await coordinator
                .RemoveAsync(rule.ManagedRuleId, actor, cancellationToken)
                .ConfigureAwait(false);
            if (!removed.Success)
            {
                failures++;
            }
        }

        var disabled = settings with
        {
            Enabled = false,
            AgentLockdown = false,
            Decisions = [],
            Pending = [],
            Dismissals = [],
            EnabledUtc = null,
        };

        ProtectionWriteConsent.Set(false);
        _ = store.Save(disabled);

        LogDisabled(logger, actor, failures);

        return await GetStatusAsync(
            failures == 0 ? null : $"{failures} Axiom-owned rule(s) could not be removed.",
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProtectionStatus> DecideAsync(
        ProtectionDecideRequest request,
        string actor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var settings = store.Load();
        if (!settings.Enabled)
        {
            return await GetStatusAsync("Axiom Shield is off.", cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(request.AppPath) ||
            !Path.IsPathFullyQualified(request.AppPath))
        {
            return await GetStatusAsync(
                "A decision needs an absolute executable path.",
                cancellationToken).ConfigureAwait(false);
        }

        var ruleId = RuleIdentity.ForApp(request.AppPath, FirewallDirection.Outbound);
        string? error = null;

        if (request.Action == ProtectionDecisionAction.Block)
        {
            var spec = new RuleSpec
            {
                ManagedRuleId = ruleId,
                AppPath = request.AppPath,
                Direction = FirewallDirection.Outbound,
                Action = FirewallAction.Block,
                Profiles = FirewallProfile.All,
                Protocol = NetworkProtocol.Any,
                CreatedBy = actor,
                Description = $"Axiom Shield block for {request.AppName}",
            };

            var result = await coordinator.ApplyAsync(spec, actor, cancellationToken).ConfigureAwait(false);
            if (!result.Success)
            {
                return await GetStatusAsync(
                    $"Block failed: {result.ErrorCode} - {result.ErrorMessage}",
                    cancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            var existing = (await coordinator.ListAsync(cancellationToken).ConfigureAwait(false))
                .FirstOrDefault(rule => rule.ManagedRuleId == ruleId);
            if (existing is not null)
            {
                var removed = await coordinator
                    .RemoveAsync(ruleId, actor, cancellationToken)
                    .ConfigureAwait(false);
                if (!removed.Success)
                {
                    error = $"Could not remove the existing block: {removed.ErrorMessage}";
                }
            }
        }

        var decisions = (settings.Decisions ?? [])
            .Where(decision => !string.Equals(decision.AppPath, request.AppPath, StringComparison.OrdinalIgnoreCase))
            .Append(new ProtectionDecision
            {
                AppPath = request.AppPath,
                AppName = request.AppName,
                Action = request.Action,
                DecidedUtc = DateTimeOffset.UtcNow,
                ManagedRuleId = request.Action == ProtectionDecisionAction.Block ? ruleId : null,
            })
            .ToList();
        var pending = (settings.Pending ?? [])
            .Where(item => !string.Equals(item.AppPath, request.AppPath, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var dismissals = (settings.Dismissals ?? [])
            .Where(item => !string.Equals(item.AppPath, request.AppPath, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (!store.Save(settings with
            {
                Decisions = decisions,
                Pending = pending,
                Dismissals = dismissals,
            }))
        {
            error = $"Decision was applied but could not be saved to {store.FilePath}.";
        }

        return await GetStatusAsync(error, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProtectionStatus> DismissAsync(
        ProtectionDismissRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var settings = store.Load();
        if (!settings.Enabled)
        {
            return await GetStatusAsync("Axiom Shield is off.", cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(request.AppPath) ||
            !Path.IsPathFullyQualified(request.AppPath))
        {
            return await GetStatusAsync(
                "Dismiss needs an absolute executable path.",
                cancellationToken).ConfigureAwait(false);
        }

        var now = DateTimeOffset.UtcNow;
        var pending = (settings.Pending ?? [])
            .Where(item => !string.Equals(item.AppPath, request.AppPath, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var dismissals = (settings.Dismissals ?? [])
            .Where(item => !string.Equals(item.AppPath, request.AppPath, StringComparison.OrdinalIgnoreCase))
            .Append(new ProtectionDismissal
            {
                AppPath = request.AppPath,
                DismissedUtc = now,
            })
            .OrderByDescending(item => item.DismissedUtc)
            .Take(200)
            .ToList();

        var error = store.Save(settings with
        {
            Pending = pending,
            Dismissals = dismissals,
        })
            ? null
            : $"Dismissal could not be saved to {store.FilePath}.";

        return await GetStatusAsync(error, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProtectionStatus> SetAgentLockdownAsync(
        bool enabled,
        string actor,
        CancellationToken cancellationToken)
    {
        var settings = store.Load();
        if (!settings.Enabled)
        {
            return await GetStatusAsync("Enable Axiom Shield before locking agents down.", cancellationToken)
                .ConfigureAwait(false);
        }

        var decisions = (settings.Decisions ?? []).ToList();
        string? error = null;

        if (enabled)
        {
            var agentPaths = (snapshots.Latest?.Connections ?? [])
                .Select(connection => connection.AppPath)
                .Where(path => AgentExecutables.IsAgentPath(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (agentPaths.Count == 0)
            {
                return await GetStatusAsync(
                    "No agent executable is connected right now, so there is nothing to lock down.",
                    cancellationToken).ConfigureAwait(false);
            }

            foreach (var path in agentPaths)
            {
                var ruleId = RuleIdentity.ForApp(path, FirewallDirection.Outbound);
                var spec = new RuleSpec
                {
                    ManagedRuleId = ruleId,
                    AppPath = path,
                    Direction = FirewallDirection.Outbound,
                    Action = FirewallAction.Block,
                    Profiles = FirewallProfile.All,
                    Protocol = NetworkProtocol.Any,
                    RemoteAddresses = NonLoopbackRanges.All,
                    CreatedBy = actor,
                    Description = "Axiom Shield agent lockdown (localhost only)",
                };

                RuleApplyResult result;
                try
                {
                    result = await coordinator.ApplyAsync(spec, actor, cancellationToken).ConfigureAwait(false);
                }
#pragma warning disable CA1031 // One agent must not abort the whole lockdown.
                catch (Exception exception)
#pragma warning restore CA1031
                {
                    LogRuleFailure(logger, path, exception);
                    error = $"Agent lockdown failed for {Path.GetFileName(path)}: {exception.Message}";
                    continue;
                }

                if (!result.Success)
                {
                    error = $"Agent lockdown failed for {Path.GetFileName(path)}: {result.ErrorMessage}";
                    continue;
                }

                decisions.RemoveAll(decision =>
                    string.Equals(decision.AppPath, path, StringComparison.OrdinalIgnoreCase));
                decisions.Add(new ProtectionDecision
                {
                    AppPath = path,
                    AppName = Path.GetFileName(path),
                    Action = ProtectionDecisionAction.Block,
                    DecidedUtc = DateTimeOffset.UtcNow,
                    IsAgentLockdown = true,
                    ManagedRuleId = ruleId,
                });
            }
        }
        else
        {
            foreach (var decision in decisions.Where(decision => decision.IsAgentLockdown).ToList())
            {
                await coordinator.RemoveAsync(
                    RuleIdentity.ForApp(decision.AppPath, FirewallDirection.Outbound),
                    actor,
                    cancellationToken).ConfigureAwait(false);
                decisions.Remove(decision);
            }
        }

        if (!store.Save(settings with { AgentLockdown = enabled, Decisions = decisions }))
        {
            error ??= $"Lockdown state could not be written to {store.FilePath}.";
        }

        return await GetStatusAsync(error, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Re-applies the agent lockdown to executables that appeared after the switch was enabled.
    /// Idempotent: the deterministic rule id is upserted, so repeated calls are cheap.
    /// </summary>
    /// <summary>
    /// Applies an existing decision to an updated install path. An application that was allowed or
    /// blocked in one versioned folder keeps that decision when the updater moves it to a new
    /// version or hash folder, instead of asking again. A block also creates the outbound rule for
    /// the new path.
    /// </summary>
    public async Task ReconcileDecisionsAsync(string actor, CancellationToken cancellationToken)
    {
        var settings = store.Load();
        if (!settings.Enabled)
        {
            return;
        }

        var connections = snapshots.Latest?.Connections;
        if (connections is null || connections.Count == 0)
        {
            return;
        }

        var decisions = (settings.Decisions ?? []).ToList();
        var exact = new HashSet<string>(
            decisions.Select(decision => decision.AppPath),
            StringComparer.OrdinalIgnoreCase);
        var families = new Dictionary<string, ProtectionDecision>(StringComparer.OrdinalIgnoreCase);
        foreach (var decision in decisions.Where(decision => !decision.IsAgentLockdown))
        {
            families[ProtectionPathFamily.Key(decision.AppPath)] = decision;
        }

        var changed = false;
        foreach (var path in connections
                     .Select(connection => connection.AppPath)
                     .Where(path => !string.IsNullOrWhiteSpace(path))
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (exact.Contains(path) ||
                !families.TryGetValue(ProtectionPathFamily.Key(path), out var family))
            {
                continue;
            }

            Guid? ruleId = null;
            if (family.Action == ProtectionDecisionAction.Block)
            {
                var candidate = RuleIdentity.ForApp(path, FirewallDirection.Outbound);
                var spec = new RuleSpec
                {
                    ManagedRuleId = candidate,
                    AppPath = path,
                    Direction = FirewallDirection.Outbound,
                    Action = FirewallAction.Block,
                    Profiles = FirewallProfile.All,
                    Protocol = NetworkProtocol.Any,
                    CreatedBy = actor,
                    Description = $"Axiom Shield block for {Path.GetFileName(path)} (updated path)",
                };

                var result = await coordinator.ApplyAsync(spec, actor, cancellationToken).ConfigureAwait(false);
                if (!result.Success)
                {
                    continue;
                }

                ruleId = candidate;
            }

            decisions.Add(new ProtectionDecision
            {
                AppPath = path,
                AppName = Path.GetFileName(path),
                Action = family.Action,
                DecidedUtc = DateTimeOffset.UtcNow,
                ManagedRuleId = ruleId,
            });
            exact.Add(path);
            changed = true;
        }

        if (changed)
        {
            _ = store.Save(settings with { Decisions = decisions });
        }
    }

    public async Task ReconcileAgentLockdownAsync(string actor, CancellationToken cancellationToken)
    {
        var settings = store.Load();
        if (!settings.Enabled || !settings.AgentLockdown)
        {
            return;
        }

        var agentPaths = (snapshots.Latest?.Connections ?? [])
            .Select(connection => connection.AppPath)
            .Where(path => AgentExecutables.IsAgentPath(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var known = (settings.Decisions ?? [])
            .Where(decision => decision.IsAgentLockdown)
            .Select(decision => decision.AppPath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var updated = (settings.Decisions ?? []).ToList();
        var changed = false;

        foreach (var path in agentPaths.Where(path => !known.Contains(path)))
        {
            var ruleId = RuleIdentity.ForApp(path, FirewallDirection.Outbound);
            var spec = new RuleSpec
            {
                ManagedRuleId = ruleId,
                AppPath = path,
                Direction = FirewallDirection.Outbound,
                Action = FirewallAction.Block,
                Profiles = FirewallProfile.All,
                Protocol = NetworkProtocol.Any,
                RemoteAddresses = NonLoopbackRanges.All,
                CreatedBy = actor,
                Description = "Axiom Shield agent lockdown (localhost only)",
            };

            var result = await coordinator.ApplyAsync(spec, actor, cancellationToken).ConfigureAwait(false);
            if (!result.Success)
            {
                continue;
            }

            updated.Add(new ProtectionDecision
            {
                AppPath = path,
                AppName = Path.GetFileName(path),
                Action = ProtectionDecisionAction.Block,
                DecidedUtc = DateTimeOffset.UtcNow,
                IsAgentLockdown = true,
                ManagedRuleId = ruleId,
            });
            changed = true;
        }

        if (changed)
        {
            _ = store.Save(settings with { Decisions = updated });
        }
    }

    private static string CurrentAccount()
    {
        try
        {
            return OperatingSystem.IsWindows()
                ? WindowsIdentity.GetCurrent().Name
                : Environment.UserName;
        }
#pragma warning disable CA1031 // The account name is display-only.
        catch (Exception)
#pragma warning restore CA1031
        {
            return "unknown";
        }
    }
}
