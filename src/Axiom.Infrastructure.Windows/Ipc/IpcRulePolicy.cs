// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Infrastructure.Windows.Ipc;

/// <summary>
/// Rule shapes the local pipe refuses even when the calling SID is the allowed user. Inbound
/// allow is the one rule that opens a listening port to the network; the interactive UI cannot
/// request it either, so refusing it costs no legitimate feature and removes the most damaging
/// command from a same-user caller.
/// </summary>
public static class IpcRulePolicy
{
    public static bool IsRejected(RuleSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return spec.Direction == FirewallDirection.Inbound &&
               spec.Action == FirewallAction.Allow;
    }
}
