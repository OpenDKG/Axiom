// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Firewall;
using Netpetra.Core.Firewall;

namespace Netpetra.Service.Tests;

/// <summary>In-memory firewall adapter used to test the coordinator without touching the OS.</summary>
internal sealed class FakeFirewallPolicyAdapter : IFirewallPolicyAdapter
{
    public List<ManagedRule> Rules { get; } = [];

    public bool FailNextApply { get; set; }

    public bool FailNextRemove { get; set; }

    public int UpsertCalls { get; private set; }

    public int RemoveCalls { get; private set; }

    public int VerifyCalls { get; private set; }

    public Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct) =>
        Task.FromResult(new FirewallCapabilityReport
        {
            Status = FirewallCapabilityStatus.Available,
            ManagedRulesReadable = true,
            ManagedRuleCount = Rules.Count,
        });

    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<ManagedRule>>(Rules.ToList());

    public Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        UpsertCalls++;

        if (FailNextApply)
        {
            return Task.FromResult(new RuleApplyResult
            {
                Success = false,
                ManagedRuleId = spec.ManagedRuleId,
                State = RuleState.Failed,
                ErrorCode = "fake.apply_failed",
                ErrorMessage = "The fake adapter refused the rule.",
            });
        }

        var name = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction);
        var verified = DateTimeOffset.UtcNow;
        Rules.RemoveAll(rule => rule.ManagedRuleId == spec.ManagedRuleId);
        Rules.Add(new ManagedRule
        {
            ManagedRuleId = spec.ManagedRuleId,
            OsRuleName = name,
            Spec = spec,
            State = RuleState.Applied,
            LastVerifiedUtc = verified,
        });

        return Task.FromResult(new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = spec.ManagedRuleId,
            State = RuleState.Applied,
            OsRuleName = name,
            VerifiedUtc = verified,
        });
    }

    public Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct)
    {
        RemoveCalls++;

        if (FailNextRemove)
        {
            return Task.FromResult(new RuleApplyResult
            {
                Success = false,
                ManagedRuleId = managedRuleId,
                State = RuleState.Failed,
                ErrorCode = "fake.remove_failed",
                ErrorMessage = "The fake adapter refused the removal.",
            });
        }

        Rules.RemoveAll(rule => rule.ManagedRuleId == managedRuleId);
        return Task.FromResult(new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = managedRuleId,
            State = RuleState.Desired,
            VerifiedUtc = DateTimeOffset.UtcNow,
        });
    }

    public Task<EffectiveRuleReport> VerifyAsync(Guid managedRuleId, CancellationToken ct)
    {
        VerifyCalls++;
        var rule = Rules.FirstOrDefault(candidate => candidate.ManagedRuleId == managedRuleId);

        return Task.FromResult(new EffectiveRuleReport
        {
            ManagedRuleId = managedRuleId,
            PresentInOs = rule is not null,
            MatchesSpec = rule is not null,
            EffectiveAction = rule?.Spec.Action,
            Notes = rule is null ? ["No fake rule present."] : [],
        });
    }
}
