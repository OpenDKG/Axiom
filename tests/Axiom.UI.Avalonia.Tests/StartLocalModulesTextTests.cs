// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The "Start local modules" result points to Complete setup and reports guard status accurately
/// on Unix. Windows keeps the existing graphical setup and repair instructions.
/// </summary>
public sealed class StartLocalModulesTextTests
{
    [Fact]
    public void Start_local_modules_result_matches_across_all_desktop_platforms()
    {
        Assert.True(OptionalModuleInstaller.IsInstallSupported);
        Assert.Equal(
            "Local modules are up: DKG node and Blackbox dashboard connected.",
            SecurityPageViewModel.StartLocalModulesResultText(dkgUp: true, blackboxUp: true));
        Assert.Equal(
            "Blackbox is up. DKG is still offline, so local blocking works but shared-graph evidence is unavailable.",
            SecurityPageViewModel.StartLocalModulesResultText(dkgUp: false, blackboxUp: true));
        Assert.Equal(
            "DKG is up. Blackbox is still offline, so agent protection is not enforcing; use Repair on its card.",
            SecurityPageViewModel.StartLocalModulesResultText(dkgUp: true, blackboxUp: false));
        Assert.Equal(
            "Neither local module answered. Install or Repair each card, then try Start local modules again.",
            SecurityPageViewModel.StartLocalModulesResultText(dkgUp: false, blackboxUp: false));
    }
}
