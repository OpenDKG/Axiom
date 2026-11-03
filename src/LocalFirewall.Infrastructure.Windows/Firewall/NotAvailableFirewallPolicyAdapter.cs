// SPDX-License-Identifier: GPL-3.0-or-later
using LocalFirewall.Contracts.Firewall;
using LocalFirewall.Core.Firewall;

namespace LocalFirewall.Infrastructure.Windows.Firewall;

/// <summary>
/// Honest placeholder for the Windows Firewall COM adapter. It reports the capability as
/// unavailable and refuses every operation instead of pretending to apply rules.
/// The real adapter (INetFwPolicy2/INetFwRule with read-back verification) arrives in FND-006.
/// </summary>
public sealed class NotAvailableFirewallPolicyAdapter : IFirewallPolicyAdapter
{
    public const string UnavailableReason =
        "Windows Firewall policy adapter is not implemented in FND-001; read-only monitoring and rule management arrive in later milestones.";

    public Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(new FirewallCapabilityReport
        {
            Status = FirewallCapabilityStatus.Unavailable,
            Reason = UnavailableReason,
            FirewallServiceRunning = null,
            ManagedRulesReadable = false,
            ManagedRuleCount = null,
        });
    }

    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct) =>
        throw new NotSupportedException(UnavailableReason);

    public Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct) =>
        throw new NotSupportedException(UnavailableReason);

    public Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct) =>
        throw new NotSupportedException(UnavailableReason);

    public Task<EffectiveRuleReport> VerifyAsync(Guid managedRuleId, CancellationToken ct) =>
        throw new NotSupportedException(UnavailableReason);
}
