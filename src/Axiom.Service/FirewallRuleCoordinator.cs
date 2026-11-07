// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Persistence;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

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

            // A failed update must leave the previously applied specification restorable: the
            // adapter keeps that policy in force, so the stored record must not become the failed
            // replacement with state Failed (startup restore only replays Applied rules).
            var previous = (await store.ListFirewallRulesAsync(cancellationToken).ConfigureAwait(false))
                .FirstOrDefault(rule => rule.ManagedRuleId == spec.ManagedRuleId);

            await store.SaveFirewallRuleAsync(pending, actorSid, "rule.apply", "pending", null, cancellationToken: cancellationToken)
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

                    await store.SaveFirewallRuleAsync(applied, actorSid, "rule.apply", "applied", null, cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    return result;
                }

                var failed = FailureRecord(pending, previous, result.ErrorCode);

                await store.SaveFirewallRuleAsync(
                    failed,
                    actorSid,
                    "rule.apply",
                    "failed",
                    result.ErrorMessage,
                    auditedSpec: spec,
                    cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return result;
            }
#pragma warning disable CA1031 // The adapter boundary must turn any failure into an audited result.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogApplyFailure(logger, exception);

                var failed = FailureRecord(pending, previous, "rule.apply_exception");

                await store.SaveFirewallRuleAsync(
                    failed,
                    actorSid,
                    "rule.apply",
                    "failed",
                    exception.Message,
                    auditedSpec: spec,
                    cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return Failed(spec.ManagedRuleId, "rule.apply_exception", exception.Message);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// The record to persist after a failed apply: the previously applied rule when there is one,
    /// otherwise the failed attempt. The failed attempt still reaches the audit trail.
    /// </summary>
    private static ManagedRule FailureRecord(ManagedRule pending, ManagedRule? previous, string? errorCode) =>
        previous is { State: RuleState.Applied }
            ? previous with { LastErrorCode = errorCode }
            : pending with { State = RuleState.Failed, LastErrorCode = errorCode };

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
