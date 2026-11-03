// SPDX-License-Identifier: GPL-3.0-or-later
using LocalFirewall.Contracts.Firewall;

namespace LocalFirewall.Core.Firewall;

/// <summary>
/// The only port through which LocalFirewall may change OS firewall state. Implemented by
/// <c>LocalFirewall.Infrastructure.Windows</c>; the UI never sees this interface.
/// </summary>
public interface IFirewallPolicyAdapter
{
    Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct);

    Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct);

    Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct);

    Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct);

    Task<EffectiveRuleReport> VerifyAsync(Guid managedRuleId, CancellationToken ct);
}
