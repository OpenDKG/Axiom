// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.UI.ViewModels;

/// <summary>
/// Agent protection page. Reuses the existing SecurityViewModel probe/timer so there is one
/// module state machine; the Security page exposes only reputation, community and file scan.
/// </summary>
public sealed class AgentsViewModel : PageViewModel
{
    public AgentsViewModel(SecurityViewModel security)
        : base("Agents", "DKG, Blackbox and the workspaces they protect", "\uE99A")
    {
        Security = security ?? throw new ArgumentNullException(nameof(security));
    }

    public SecurityViewModel Security { get; }
}
