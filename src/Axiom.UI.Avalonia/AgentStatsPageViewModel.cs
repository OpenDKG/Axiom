// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Statistics surface for agent activity. It reuses the Agents data source so the two pages never
/// disagree: the audit feed, sessions, hook evidence and findings stay in one place, and this view
/// only presents them with their counters.
/// </summary>
public sealed class AgentStatsPageViewModel : PageViewModel, IActivatablePage
{
    public AgentStatsPageViewModel(AgentsPageViewModel agents)
        : base("Agent Activity", "Recorded agent activity, sessions, hook evidence and findings", "S")
    {
        Agents = agents ?? throw new ArgumentNullException(nameof(agents));
    }

    public AgentsPageViewModel Agents { get; }

    public void Activate() => Agents.Activate();

    public void Deactivate() => Agents.Deactivate();
}
