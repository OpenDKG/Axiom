// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class OptionalModuleInstallerScriptTests
{
    [Fact]
    public void Dkg_script_feeds_default_answers_so_a_full_install_cannot_hang()
    {
        var installer = new OptionalModuleInstaller();
        var build = typeof(OptionalModuleInstaller).GetMethod(
            "BuildDkgScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var script = (string)build.Invoke(installer, null)!;

        Assert.Contains("$answers = 1..14", script, StringComparison.Ordinal);
        Assert.Contains("$answers | & $dkg init", script, StringComparison.Ordinal);
        Assert.Contains("-y", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Answer the prompts", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Blackbox_script_prepends_the_discovered_tool_folders()
    {
        var installer = new OptionalModuleInstaller();
        var build = typeof(OptionalModuleInstaller).GetMethod(
            "BuildBlackboxScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var script = (string)build.Invoke(installer, null)!;

        Assert.Contains("$env:PATH", script, StringComparison.Ordinal);
        Assert.Contains("blackbox-install.ps1", script, StringComparison.Ordinal);
        Assert.Contains("ARGS:-3.12", script, StringComparison.Ordinal);
        Assert.Contains("vcruntime140.dll", script, StringComparison.Ordinal);
        Assert.Contains("oxigraph-worker", script, StringComparison.Ordinal);
    }
}
