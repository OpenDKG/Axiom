// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
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
    public void Pinned_blackbox_build_is_reused_when_the_marker_and_venv_match()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-bb-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "agent-blackbox", "venv", "Scripts"));
            File.WriteAllText(Path.Combine(root, "agent-blackbox", "venv", "Scripts", "python.exe"), string.Empty);
            Assert.False(OptionalModuleInstaller.IsPinnedBuildInstalledAt(root));

            File.WriteAllText(Path.Combine(root, ".axiom-blackbox-build"), "deadbeef");
            Assert.False(OptionalModuleInstaller.IsPinnedBuildInstalledAt(root));

            File.WriteAllText(
                Path.Combine(root, ".axiom-blackbox-build"),
                "261122F5E879596E88D63C30D5D36D12B4E155986F83AA3EB83ADEB406E41179");
            Assert.True(OptionalModuleInstaller.IsPinnedBuildInstalledAt(root));

            File.Delete(Path.Combine(root, "agent-blackbox", "venv", "Scripts", "python.exe"));
            Assert.False(OptionalModuleInstaller.IsPinnedBuildInstalledAt(root));
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
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
        Assert.Contains("'auto'", script, StringComparison.Ordinal);
        Assert.DoesNotContain("oxigraph-worker", script, StringComparison.Ordinal);
        Assert.DoesNotContain("*> $null", script, StringComparison.Ordinal);
        Assert.Contains("$ErrorActionPreference = 'Continue'", script, StringComparison.Ordinal);
        Assert.Contains("& $installer -StoreBackend $storeBackend", script, StringComparison.Ordinal);
        Assert.Contains("if sys.stdout is None:", script, StringComparison.Ordinal);
        Assert.Contains("if sys.stderr is None:", script, StringComparison.Ordinal);
        Assert.Contains("os.devnull", script, StringComparison.Ordinal);
        Assert.Contains("if sys.stdout is None:", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        Assert.Contains("if sys.stderr is None:", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
    }
}
