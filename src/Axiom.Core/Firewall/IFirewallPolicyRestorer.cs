// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Core.Firewall;

/// <summary>
/// Optional startup hook for adapters whose enforcement state is owned by the service process
/// instead of by the OS. The Linux eBPF backend loses its maps when the service exits, so applied
/// rules are re-applied from the audited store when the write gate is open.
/// </summary>
public interface IFirewallPolicyRestorer
{
    Task RestoreAsync(IReadOnlyList<RuleSpec> specs, CancellationToken cancellationToken);
}
