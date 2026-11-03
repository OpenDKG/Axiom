// SPDX-License-Identifier: GPL-3.0-or-later
namespace LocalFirewall.UI.ViewModels;

public sealed class AlertsViewModel : PageViewModel
{
    public AlertsViewModel()
        : base("Alerts", "Notifications · blocker evidence arrives with FND-007", "\uE7BA")
    {
    }

    public IReadOnlyList<string> PlannedCapabilities { get; } =
    [
        "First-seen application alert with deduplication and quiet hours.",
        "Blocked-attempt evidence only when a rule/filter correlation is verified.",
        "Unattributed blocks are labelled “source unknown”, never guessed.",
        "Per-alert snooze, rate limiting and no focus-stealing popups.",
    ];
}
