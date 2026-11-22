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
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Off_windows_the_result_never_points_to_repair_or_guided_install(bool dkgUp, bool blackboxUp)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.False(OptionalModuleInstaller.IsInstallSupported);
        var text = SecurityPageViewModel.StartLocalModulesResultText(dkgUp, blackboxUp);

        Assert.DoesNotContain("Repair", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("guided", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Install or", text, StringComparison.Ordinal);
        if (!blackboxUp)
        {
            Assert.Contains("manually", text, StringComparison.Ordinal);
            Assert.Contains("--complete", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Off_windows_dashboard_up_without_dkg_does_not_claim_blocking()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var text = SecurityPageViewModel.StartLocalModulesResultText(dkgUp: false, blackboxUp: true);

        Assert.Contains("blocking in the agent host remains unverified", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Windows_keeps_the_install_or_repair_text()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.Equal(
            "Neither local module answered. Install or Repair each card, then try Start local modules again.",
            SecurityPageViewModel.StartLocalModulesResultText(dkgUp: false, blackboxUp: false));
        Assert.Equal(
            "DKG is up. Blackbox is still offline, so agent protection is not enforcing; use Repair on its card.",
            SecurityPageViewModel.StartLocalModulesResultText(dkgUp: true, blackboxUp: false));
    }
}
