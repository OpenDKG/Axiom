// SPDX-License-Identifier: GPL-3.0-or-later
namespace LocalFirewall.UI.ViewModels;

/// <summary>
/// Firewall rules page. Deliberately exposes no write command: this build has no firewall adapter,
/// so the honest state is "unavailable" and "0 owned rules known to this build".
/// </summary>
public sealed class FirewallRulesViewModel : PageViewModel
{
    public FirewallRulesViewModel()
        : base("Firewall Rules", "Owned rule inventory · this build cannot read or change Windows Firewall", "\uE72E")
    {
    }

    public string CapabilityStatusText => "Adapter unavailable";

    public string CapabilityDetail =>
        "The INetFwPolicy2/INetFwRule adapter is scheduled for FND-006. Until then LocalFirewall reads no " +
        "Windows Firewall rule, creates no rule and removes no rule.";

    public string OwnedRuleCountText => "0";

    public string PolicyCheckNote =>
        "Recheck is disabled: there is no policy read path yet, so any result shown here would be invented.";

    public IReadOnlyList<string> PlannedScopeNotes { get; } =
    [
        "Rules will be bound to an absolute executable path, direction and Windows profile.",
        "Every owned rule is named LocalFirewall::{rule-id}::{OUT|IN} for targeted removal.",
        "Apply is only reported as success after a read-back of the created rule.",
        "An external block or GPO remains authoritative; the UI will show a conflict, not a fake allow.",
    ];
}
