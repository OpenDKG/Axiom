// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Firewall;
using Axiom.Core.Enforcement;

namespace Axiom.Service;

/// <summary>Abstracts one outbound TCP probe used by the Stage E4 dual-destination canary.</summary>
public interface IAgentNetworkCanaryProbe
{
    Task<bool> TryConnectAsync(IPEndPoint endpoint, CancellationToken cancellationToken);
}

/// <summary>Standard TCP connect probe with a short bounded timeout for disposable E4 canary tests.</summary>
public sealed class TcpAgentNetworkCanaryProbe(TimeSpan? timeout = null) : IAgentNetworkCanaryProbe
{
    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(2);

    public async Task<bool> TryConnectAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);
        using var client = new TcpClient(endpoint.AddressFamily);

        try
        {
            await client.ConnectAsync(endpoint.Address, endpoint.Port, cts.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            return false;
        }
    }
}

public sealed record AgentFirewallApplyOutcome(
    bool Applied,
    bool ReadbackVerified,
    Guid? ManagedRuleId,
    string? ErrorCode,
    string? Message,
    EnforcementReceiptV1 Receipt);

public sealed record AgentFirewallCanaryOutcome(
    bool Verified,
    DualDestinationCanaryObservation Observation,
    EnforcementReceiptV1 Receipt);

public sealed record AgentFirewallRollbackReport(
    int RemovedCount,
    int OrphanedCount,
    IReadOnlyList<Guid> RemainingRuleIds);

/// <summary>
/// Stage E4 coordinator: applies opt-in, scoped per-agent outbound Windows Firewall rules through
/// <see cref="FirewallRuleCoordinator"/>, verifies read-back without claiming OS enforcement from a
/// write ACK alone, runs dual-destination canary verification before emitting <c>OS_DENY_VERIFIED</c>,
/// and cleanly rolls back only its tracked Axiom-owned rules.
/// </summary>
public sealed class AgentFirewallEnforcer(
    FirewallRuleCoordinator coordinator,
    EnforcementReceiptJournal? journal = null,
    IAgentNetworkCanaryProbe? probe = null)
{
    private readonly FirewallRuleCoordinator _coordinator =
        coordinator ?? throw new ArgumentNullException(nameof(coordinator));

    private readonly EnforcementReceiptJournal? _journal = journal;
    private readonly IAgentNetworkCanaryProbe _probe = probe ?? new TcpAgentNetworkCanaryProbe();
    private readonly object _gate = new();
    private readonly HashSet<Guid> _trackedRules = [];

    public IReadOnlyCollection<Guid> TrackedRuleIds
    {
        get
        {
            lock (_gate)
            {
                return [.. _trackedRules];
            }
        }
    }

    public async Task<AgentFirewallApplyOutcome> ApplyScopedBlockAsync(
        AgentFirewallRuleIntent intent,
        string requestId,
        DateTimeOffset utcTime,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        var plan = AgentFirewallRulePlanner.BuildScopedBlockSpec(intent);
        if (!plan.IsAllowedToWriteOsRule || plan.Spec is null)
        {
            var reason = plan.RejectionReasonCode ?? EnforcementReasonCodes.CommunityAdvisoryOnly;
            var advisoryReceipt = RecordReceipt(
                eventId: $"{requestId}:e4:rejected",
                requestId: requestId,
                policyRevision: intent.PolicyRevision,
                executablePath: intent.ExecutablePath,
                decisionSource: reason,
                requestedDecision: EnforcementDecision.Audit,
                boundary: EnforcementBoundaryKind.DetectorOnly,
                result: EnforcementReceiptResult.AuditOnly,
                sideEffect: EnforcementObservedSideEffect.Unknown,
                verifiedBy: null,
                timestampUtc: utcTime);

            return new AgentFirewallApplyOutcome(
                Applied: false,
                ReadbackVerified: false,
                ManagedRuleId: null,
                ErrorCode: reason,
                Message: plan.RejectionMessage,
                Receipt: advisoryReceipt);
        }

        var spec = plan.Spec;
        var apply = await _coordinator.ApplyAsync(spec, intent.ActorSid, cancellationToken).ConfigureAwait(false);
        if (!apply.Success)
        {
            var failReceipt = RecordReceipt(
                eventId: $"{requestId}:e4:apply-failed",
                requestId: requestId,
                policyRevision: intent.PolicyRevision,
                executablePath: spec.AppPath,
                decisionSource: apply.ErrorCode ?? "rule.apply_failed",
                requestedDecision: EnforcementDecision.Block,
                boundary: EnforcementBoundaryKind.OsFirewall,
                result: EnforcementReceiptResult.Unverified,
                sideEffect: EnforcementObservedSideEffect.Unknown,
                verifiedBy: null,
                timestampUtc: utcTime);

            return new AgentFirewallApplyOutcome(
                Applied: false,
                ReadbackVerified: false,
                ManagedRuleId: null,
                ErrorCode: apply.ErrorCode,
                Message: apply.ErrorMessage,
                Receipt: failReceipt);
        }

        lock (_gate)
        {
            _trackedRules.Add(spec.ManagedRuleId);
        }

        var readback = await _coordinator.VerifyAsync(spec.ManagedRuleId, cancellationToken).ConfigureAwait(false);
        var readbackOk = readback.PresentInOs && readback.MatchesSpec && readback.EffectiveAction == FirewallAction.Block;

        // Read-back confirms rule presence only; OS_DENY_VERIFIED requires an observed absent side effect via canary.
        var receipt = RecordReceipt(
            eventId: $"{requestId}:e4:applied",
            requestId: requestId,
            policyRevision: intent.PolicyRevision,
            executablePath: spec.AppPath,
            decisionSource: "firewall_rule_readback",
            requestedDecision: EnforcementDecision.Block,
            boundary: EnforcementBoundaryKind.OsFirewall,
            result: readbackOk ? EnforcementReceiptResult.DenyRequested : EnforcementReceiptResult.Unverified,
            sideEffect: EnforcementObservedSideEffect.Unknown,
            verifiedBy: null,
            timestampUtc: utcTime);

        return new AgentFirewallApplyOutcome(
            Applied: true,
            ReadbackVerified: readbackOk,
            ManagedRuleId: spec.ManagedRuleId,
            ErrorCode: readbackOk ? null : "rule.readback_mismatch",
            Message: readbackOk
                ? "Scoped OS firewall rule verified by read-back; dual-destination canary required before OS_DENY_VERIFIED."
                : string.Join("; ", readback.Notes),
            Receipt: receipt);
    }

    public async Task<AgentFirewallCanaryOutcome> VerifyDualDestinationCanaryAsync(
        Guid managedRuleId,
        string executablePath,
        IPEndPoint blockedEndpoint,
        IPEndPoint permittedControlEndpoint,
        string policyRevision,
        string requestId,
        DateTimeOffset utcTime,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(blockedEndpoint);
        ArgumentNullException.ThrowIfNull(permittedControlEndpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        var readback = await _coordinator.VerifyAsync(managedRuleId, cancellationToken).ConfigureAwait(false);
        var osRuleOk = readback.PresentInOs && readback.MatchesSpec && readback.EffectiveAction == FirewallAction.Block;

        var blockedConnected = await _probe.TryConnectAsync(blockedEndpoint, cancellationToken).ConfigureAwait(false);
        var permittedConnected = await _probe.TryConnectAsync(permittedControlEndpoint, cancellationToken).ConfigureAwait(false);

        var deniedBlocked = !blockedConnected;
        var verified = osRuleOk && deniedBlocked && permittedConnected;

        var observation = new DualDestinationCanaryObservation(
            BlockedEndpointDenied: deniedBlocked,
            PermittedControlEndpointSucceeded: permittedConnected,
            OsRuleReadbackVerified: osRuleOk,
            ChildProcessAttributionNote:
                "Windows Firewall rule binds to normalized executable path; child processes spawned at distinct binaries require separate rule scopes.");

        var receipt = RecordReceipt(
            eventId: $"{requestId}:e4:canary",
            requestId: requestId,
            policyRevision: policyRevision,
            executablePath: executablePath,
            decisionSource: "dual_destination_canary",
            requestedDecision: EnforcementDecision.Block,
            boundary: EnforcementBoundaryKind.OsFirewall,
            result: verified ? EnforcementReceiptResult.OsDenyVerified : EnforcementReceiptResult.Unverified,
            sideEffect: deniedBlocked ? EnforcementObservedSideEffect.Absent : EnforcementObservedSideEffect.Present,
            verifiedBy: verified ? "dual-dest-network-canary" : null,
            timestampUtc: utcTime);

        return new AgentFirewallCanaryOutcome(verified, observation, receipt);
    }

    public async Task<AgentFirewallRollbackReport> RollbackTrackedRulesAsync(
        string actorSid,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSid);

        Guid[] toRemove;
        lock (_gate)
        {
            toRemove = [.. _trackedRules];
        }

        var removed = 0;
        var remaining = new List<Guid>();

        foreach (var ruleId in toRemove)
        {
            var removal = await _coordinator.RemoveAsync(ruleId, actorSid, cancellationToken).ConfigureAwait(false);
            var verify = await _coordinator.VerifyAsync(ruleId, cancellationToken).ConfigureAwait(false);
            if (removal.Success && !verify.PresentInOs)
            {
                removed++;
                lock (_gate)
                {
                    _trackedRules.Remove(ruleId);
                }
            }
            else
            {
                remaining.Add(ruleId);
            }
        }

        return new AgentFirewallRollbackReport(removed, remaining.Count, remaining);
    }

    private EnforcementReceiptV1 RecordReceipt(
        string eventId,
        string requestId,
        string policyRevision,
        string executablePath,
        string decisionSource,
        EnforcementDecision requestedDecision,
        EnforcementBoundaryKind boundary,
        EnforcementReceiptResult result,
        EnforcementObservedSideEffect sideEffect,
        string? verifiedBy,
        DateTimeOffset timestampUtc)
    {
        var receipt = EnforcementReceiptV1.Create(
            eventId: eventId,
            requestId: requestId,
            policyRevision: policyRevision,
            hostAdapter: "windows-firewall",
            hostVersion: Environment.OSVersion.VersionString,
            actionKind: AgentActionKind.NetworkConnect,
            decisionSource: decisionSource,
            rawTargetOrIndicator: executablePath,
            requestedDecision: requestedDecision,
            boundary: boundary,
            result: result,
            observedSideEffect: sideEffect,
            verifiedBy: verifiedBy,
            timestampUtc: timestampUtc);

        _journal?.TryAppend(receipt);
        return receipt;
    }
}
