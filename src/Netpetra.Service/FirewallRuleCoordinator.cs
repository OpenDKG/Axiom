// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Firewall;
using Netpetra.Core.Firewall;
using Netpetra.Persistence;
using Microsoft.Extensions.Logging;

namespace Netpetra.Service;

/// <summary>
/// Serialises rule changes through validate -> pending -> apply -> read-back -> applied/failed and
/// writes an audit row for every step. It never deletes or edits a rule it does not own.
/// </summary>
public sealed partial class FirewallRuleCoordinator(
    IFirewallPolicyAdapter adapter,
    HistoryStore store,
    ILogger<FirewallRuleCoordinator> logger) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public void Dispose() => _gate.Dispose();

    [LoggerMessage(EventId = 4001, Level = LogLevel.Warning, Message = "Firewall rule apply failed")]
    private static partial void LogApplyFailure(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 4002, Level = LogLevel.Warning, Message = "Firewall rule removal failed")]
    private static partial void LogRemoveFailure(ILogger logger, Exception exception);

    public async Task<RuleApplyResult> ApplyAsync(
        RuleSpec spec,
        string actorSid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);

        var validation = RuleSpecValidator.Validate(spec);
        if (!validation.IsValid)
        {
            return Failed(
                spec.ManagedRuleId,
                "rule.invalid",
                string.Join("; ", validation.Errors.Select(error => $"{error.Code}: {error.Message}")));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            var pending = new ManagedRule
            {
                ManagedRuleId = spec.ManagedRuleId,
                OsRuleName = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction),
                Spec = spec,
                State = RuleState.Pending,
            };

            await store.SaveFirewallRuleAsync(pending, actorSid, "rule.apply", "pending", null, cancellationToken)
                .ConfigureAwait(false);

            try
            {
                var result = await adapter.UpsertOwnedRuleAsync(spec, cancellationToken).ConfigureAwait(false);

                if (result.Success)
                {
                    var applied = pending with
                    {
                        State = RuleState.Applied,
                        LastVerifiedUtc = result.VerifiedUtc ?? DateTimeOffset.UtcNow,
                    };

                    await store.SaveFirewallRuleAsync(applied, actorSid, "rule.apply", "applied", null, cancellationToken)
                        .ConfigureAwait(false);
                    return result;
                }

                var failed = pending with
                {
                    State = RuleState.Failed,
                    LastErrorCode = result.ErrorCode,
                };

                await store.SaveFirewallRuleAsync(failed, actorSid, "rule.apply", "failed", result.ErrorMessage, cancellationToken)
                    .ConfigureAwait(false);
                return result;
            }
#pragma warning disable CA1031 // The adapter boundary must turn any failure into an audited result.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogApplyFailure(logger, exception);

                var failed = pending with
                {
                    State = RuleState.Failed,
                    LastErrorCode = "rule.apply_exception",
                };

                await store.SaveFirewallRuleAsync(failed, actorSid, "rule.apply", "failed", exception.Message, cancellationToken)
                    .ConfigureAwait(false);
                return Failed(spec.ManagedRuleId, "rule.apply_exception", exception.Message);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RuleApplyResult> RemoveAsync(
        Guid managedRuleId,
        string actorSid,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);

        if (managedRuleId == Guid.Empty)
        {
            return Failed(Guid.Empty, "rule.id.empty", "Managed rule id must not be empty.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            try
            {
                var result = await adapter.RemoveOwnedRuleAsync(managedRuleId, cancellationToken).ConfigureAwait(false);
                if (result.Success)
                {
                    await store.DeleteFirewallRuleAsync(managedRuleId, actorSid, "removed", null, cancellationToken)
                        .ConfigureAwait(false);
                    return result;
                }

                await store.RecordFirewallRuleRemovalFailureAsync(
                    managedRuleId,
                    actorSid,
                    result.ErrorCode,
                    result.ErrorMessage,
                    cancellationToken).ConfigureAwait(false);
                return result;
            }
#pragma warning disable CA1031 // The adapter boundary must turn any failure into an audited result.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogRemoveFailure(logger, exception);
                await store.RecordFirewallRuleRemovalFailureAsync(
                    managedRuleId,
                    actorSid,
                    "rule.remove_exception",
                    exception.Message,
                    cancellationToken).ConfigureAwait(false);
                return Failed(managedRuleId, "rule.remove_exception", exception.Message);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<EffectiveRuleReport> VerifyAsync(Guid managedRuleId, CancellationToken cancellationToken)
    {
        if (managedRuleId == Guid.Empty)
        {
            return new EffectiveRuleReport
            {
                ManagedRuleId = Guid.Empty,
                PresentInOs = false,
                MatchesSpec = false,
                EffectiveAction = null,
                Notes = ["Managed rule id must not be empty."],
            };
        }

        var stored = (await store.ListFirewallRulesAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(rule => rule.ManagedRuleId == managedRuleId);
        if (stored is null)
        {
            return new EffectiveRuleReport
            {
                ManagedRuleId = managedRuleId,
                PresentInOs = false,
                MatchesSpec = false,
                EffectiveAction = null,
                Notes = ["No stored specification exists for this managed rule id."],
            };
        }

        return await adapter.VerifyAsync(stored.Spec, cancellationToken).ConfigureAwait(false);
    }

    public Task<IReadOnlyList<ManagedRule>> ListAsync(CancellationToken cancellationToken) =>
        store.ListFirewallRulesAsync(cancellationToken);

    private static RuleApplyResult Failed(Guid id, string code, string message) => new()
    {
        Success = false,
        ManagedRuleId = id,
        State = RuleState.Failed,
        ErrorCode = code,
        ErrorMessage = message,
    };
}
