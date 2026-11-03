// SPDX-License-Identifier: GPL-3.0-or-later
using Netrigil.Contracts.Firewall;

namespace Netrigil.Core.Firewall;

/// <summary>
/// The only port through which Netrigil may change OS firewall state. Implemented by
/// <c>Netrigil.Infrastructure.Windows</c>; the UI never sees this interface.
/// </summary>
public interface IFirewallPolicyAdapter
{
    Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct);

    Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct);

    Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct);

    Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct);

    Task<EffectiveRuleReport> VerifyAsync(Guid managedRuleId, CancellationToken ct);
}
