// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Enforcement;

/// <summary>
/// Deterministic, offline policy evaluator. It reads no clock, no network and no DKG data: the same
/// request, capabilities and optional guard signal always produce the same verdict.
/// </summary>
/// <remarks>
/// Precedence follows the enforcement handoff: a protected resource handled by a real boundary is
/// denied first; an agent identity that is not listed never inherits another agent's allow rules;
/// an explicit Blackbox block overrides allow rules; and DKG reputation is not an input at all.
/// </remarks>
public sealed class EnforcementPolicyEvaluator
{
    /// <summary>Upper bound on any target or process path accepted by the engine.</summary>
    public const int MaximumTargetLength = 4096;

    /// <summary>Upper bound on request, agent and session identifiers.</summary>
    public const int MaximumIdentityLength = 128;

    private const int IdempotencyCapacity = 1024;
    private const string DefaultRuleId = "policy:default";
    private const string InvalidRuleId = "policy:invalid-request";
    private const string GuardRuleId = "blackbox:guard";

    private readonly EnforcementPolicy _policy;
    private readonly Dictionary<string, AgentActionVerdict> _verdicts = new(StringComparer.Ordinal);
    private readonly Queue<string> _remembered = new();

    public EnforcementPolicyEvaluator(EnforcementPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var problems = EnforcementPolicyValidator.Validate(policy);
        if (problems.Count > 0)
        {
            throw new ArgumentException(string.Join("; ", problems), nameof(policy));
        }

        _policy = policy;
    }

    /// <summary>The policy this evaluator was built from.</summary>
    public EnforcementPolicy Policy => _policy;

    /// <summary>
    /// Evaluates one request. Repeat calls with the same <see cref="AgentActionRequest.RequestId"/>
    /// return the first verdict, so a retried hook event cannot flip a decision.
    /// </summary>
    public AgentActionVerdict Evaluate(
        AgentActionRequest request,
        EnforcementCapabilities? capabilities = null,
        BlackboxGuardSignal? guard = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        capabilities ??= new EnforcementCapabilities();

        if (!IsWellFormed(request))
        {
            return Verdict(
                request,
                EnforcementDecision.Unavailable,
                InvalidRuleId,
                EnforcementReasonCodes.InvalidRequest,
                boundary: EnforcementStrength.Observation);
        }

        if (_verdicts.TryGetValue(request.RequestId, out var cached))
        {
            return cached;
        }

        var boundary = BoundaryStrength(capabilities);
        var agent = FindAgent(request.AgentId);
        var mode = agent?.Mode ?? EnforcementMode.Monitor;

        var verdict = Decide(request, boundary, agent, mode, guard);
        Remember(request.RequestId, verdict);
        return verdict;
    }

    private AgentActionVerdict Decide(
        AgentActionRequest request,
        EnforcementStrength boundary,
        AgentEnforcementPolicy? agent,
        EnforcementMode mode,
        BlackboxGuardSignal? guard)
    {
        if (TryMatchProtected(request, out var resource))
        {
            if (boundary != EnforcementStrength.Observation)
            {
                return Verdict(
                    request,
                    EnforcementDecision.Block,
                    resource.ResourceId,
                    EnforcementReasonCodes.ProtectedResource,
                    boundary);
            }

            return mode switch
            {
                EnforcementMode.ProtectSelectedOperations => Verdict(
                    request,
                    EnforcementDecision.Ask,
                    resource.ResourceId,
                    EnforcementReasonCodes.ProtectedUnenforceable,
                    boundary,
                    requiresApproval: true),
                EnforcementMode.Ask => Verdict(
                    request,
                    EnforcementDecision.Ask,
                    resource.ResourceId,
                    EnforcementReasonCodes.ProtectedUnenforceable,
                    boundary,
                    requiresApproval: true),
                _ => Verdict(
                    request,
                    EnforcementDecision.Audit,
                    resource.ResourceId,
                    EnforcementReasonCodes.ProtectedObserved,
                    boundary),
            };
        }

        if (guard is { IsAvailable: true, IsBlock: true })
        {
            return Verdict(
                request,
                EnforcementDecision.Block,
                GuardRuleId,
                EnforcementReasonCodes.GuardBlock,
                boundary,
                signalId: guard.SignalId);
        }

        if (agent is not null)
        {
            foreach (var rule in agent.Rules)
            {
                if (!RuleMatches(rule, request))
                {
                    continue;
                }

                return rule.Effect switch
                {
                    EnforcementRuleEffect.Block => Verdict(
                        request,
                        EnforcementDecision.Block,
                        rule.RuleId,
                        EnforcementReasonCodes.RuleBlock,
                        boundary),
                    EnforcementRuleEffect.Ask => Verdict(
                        request,
                        EnforcementDecision.Ask,
                        rule.RuleId,
                        EnforcementReasonCodes.RuleAsk,
                        boundary,
                        requiresApproval: true),
                    _ => Verdict(
                        request,
                        EnforcementDecision.Allow,
                        rule.RuleId,
                        EnforcementReasonCodes.RuleAllow,
                        boundary),
                };
            }
        }

        return mode == EnforcementMode.Ask
            ? Verdict(
                request,
                EnforcementDecision.Ask,
                DefaultRuleId,
                EnforcementReasonCodes.NoRuleAsk,
                boundary,
                requiresApproval: true)
            : Verdict(
                request,
                EnforcementDecision.Audit,
                DefaultRuleId,
                EnforcementReasonCodes.NoRuleMonitor,
                boundary);
    }

    /// <summary>
    /// A guard is a detector, not a boundary: only host, broker or OS controls can raise the
    /// enforceable strength, and a host-hook deny counts only when it has been proven.
    /// </summary>
    private static EnforcementStrength BoundaryStrength(EnforcementCapabilities capabilities) =>
        capabilities.Strength switch
        {
            EnforcementStrength.OsBoundary => EnforcementStrength.OsBoundary,
            EnforcementStrength.TrustedBroker => EnforcementStrength.TrustedBroker,
            EnforcementStrength.HostHook when capabilities.HostSupportsDeny => EnforcementStrength.HostHook,
            _ => EnforcementStrength.Observation,
        };

    private static bool RuleMatches(EnforcementRule rule, AgentActionRequest request) =>
        (rule.Kind is null || rule.Kind == request.Kind)
        && EnforcementScopeMatcher.MatchesTarget(rule.TargetScope, request);

    private bool TryMatchProtected(AgentActionRequest request, out ProtectedResource resource)
    {
        foreach (var candidate in _policy.ProtectedResources)
        {
            if (candidate.Kinds.Count > 0 && !candidate.Kinds.Contains(request.Kind))
            {
                continue;
            }

            if (EnforcementScopeMatcher.MatchesTarget(candidate.Scope, request))
            {
                resource = candidate;
                return true;
            }
        }

        resource = null!;
        return false;
    }

    private AgentEnforcementPolicy? FindAgent(string agentId)
    {
        foreach (var agent in _policy.Agents)
        {
            if (agent.AgentId.Equals(agentId, StringComparison.OrdinalIgnoreCase))
            {
                return agent;
            }
        }

        return null;
    }

    private static bool IsWellFormed(AgentActionRequest request) =>
        !string.IsNullOrWhiteSpace(request.RequestId)
        && request.RequestId.Length <= MaximumIdentityLength
        && !string.IsNullOrWhiteSpace(request.AgentId)
        && request.AgentId.Length <= MaximumIdentityLength
        && Enum.IsDefined(request.Kind)
        && (request.Target?.Length ?? 0) <= MaximumTargetLength
        && (request.ProcessPath?.Length ?? 0) <= MaximumTargetLength
        && (request.SessionId?.Length ?? 0) <= MaximumIdentityLength
        && (request.ParentRequestId?.Length ?? 0) <= MaximumIdentityLength;

    private static AgentActionVerdict Verdict(
        AgentActionRequest request,
        EnforcementDecision decision,
        string ruleId,
        string reasonCode,
        EnforcementStrength boundary,
        bool requiresApproval = false,
        string? signalId = null) => new()
        {
            RequestId = request.RequestId,
            Decision = decision,
            RuleId = ruleId,
            ReasonCode = reasonCode,
            AvailableStrength = boundary,
            RequireUserApproval = requiresApproval,
            BlackboxSignalId = signalId,
            EvaluatedUtc = request.UtcTime,
        };

    private void Remember(string requestId, AgentActionVerdict verdict)
    {
        if (_verdicts.Count >= IdempotencyCapacity && _remembered.Count > 0)
        {
            var oldest = _remembered.Dequeue();
            _verdicts.Remove(oldest);
        }

        _verdicts[requestId] = verdict;
        _remembered.Enqueue(requestId);
    }
}
