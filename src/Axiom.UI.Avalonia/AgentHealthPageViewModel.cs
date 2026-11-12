// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Agent health page: protected workspaces, detected agents, hook state and runtime hook tests,
/// followed by Blackbox/DKG health and module health. It reuses the shared
/// <see cref="AgentsPageViewModel"/> and <see cref="SecurityPageViewModel"/> so the probes, timers
/// and health samples stay single-owner.
/// </summary>
public sealed class AgentHealthPageViewModel : PageViewModel, IActivatablePage
{
    public AgentHealthPageViewModel(AgentsPageViewModel agents, SecurityPageViewModel security)
        : base("Agent Health", "Protected workspaces, hook state, Blackbox and module health", "\uE95E")
    {
        AgentActivity = agents;
        Security = security;
    }

    public AgentsPageViewModel AgentActivity { get; }

    public SecurityPageViewModel Security { get; }

    public void Activate() => AgentActivity.Activate();

    public void Deactivate() => AgentActivity.Deactivate();
}
