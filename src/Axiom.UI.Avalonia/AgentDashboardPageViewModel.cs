// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Default landing page: local AI agent protection, guard decisions and findings.
/// It shares <see cref="AgentsPageViewModel"/> with Agent Protection and Agent Activity, so the
/// dashboard never loads a second copy of the same Blackbox audit.
/// </summary>
public sealed class AgentDashboardPageViewModel : PageViewModel, IActivatablePage
{
    public AgentDashboardPageViewModel(AgentsPageViewModel agents)
        : base("Agent Dashboard", "Guard decisions, agent activity and findings", "\uE9D9")
    {
        AgentActivity = agents;
    }

    public AgentsPageViewModel AgentActivity { get; }

    public void Activate() => AgentActivity.Activate();

    public void Deactivate() => AgentActivity.Deactivate();
}
