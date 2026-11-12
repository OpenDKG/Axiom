// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Agent health page: protected workspaces, detected agents, hook state and runtime hook tests.
/// It reuses <see cref="SecurityPageViewModel"/> so the protected-agent probes and their timers are
/// not duplicated; the security page remains the single owner of that state.
/// </summary>
public sealed class AgentHealthPageViewModel : PageViewModel
{
    public AgentHealthPageViewModel(SecurityPageViewModel security)
        : base("Agent Health", "Protected workspaces, hook state and runtime tests", "\uE95E")
    {
        Security = security;
    }

    public SecurityPageViewModel Security { get; }
}
