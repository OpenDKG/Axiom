// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class ModulePrerequisitesTests
{
    [Fact]
    public void Finds_every_tool_from_path()
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\tools\node\node.exe",
            @"C:\tools\node\npm.cmd",
            @"C:\tools\python\python.exe",
            @"C:\tools\git\cmd\git.exe",
        };

        var report = ModulePrerequisites.Probe(
            @"C:\tools\node;C:\tools\python;C:\tools\git\cmd",
            files.Contains);

        Assert.True(report.IsSatisfied);
        Assert.Empty(report.Missing);
        Assert.Contains(report.SearchDirectories, directory => directory.Equals(@"C:\tools\node", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Windows_store_python_alias_is_not_treated_as_python()
    {
        var storeAliases = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft",
            "WindowsApps");

        var report = ModulePrerequisites.Probe(
            storeAliases,
            candidate => candidate.StartsWith(storeAliases, StringComparison.OrdinalIgnoreCase));

        var python = Assert.Single(report.Tools, tool => tool.Tool == ModuleTool.Python);
        Assert.False(python.IsAvailable);
    }

    [Fact]
    public void Well_known_install_folder_is_used_when_path_is_stale()
    {
        // A desktop process keeps the PATH it started with, so a tool installed afterwards is only
        // visible through the default install folder.
        var report = ModulePrerequisites.Probe(
            null,
            candidate => candidate.EndsWith(@"Programs\nodejs\node.exe", StringComparison.OrdinalIgnoreCase));

        var node = Assert.Single(report.Tools, tool => tool.Tool == ModuleTool.Node);
        Assert.True(node.IsAvailable);
        Assert.EndsWith(@"Programs\nodejs", node.Directory, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Missing_summary_lists_only_missing_tools()
    {
        var report = ModulePrerequisites.Probe(
            @"C:\tools\node",
            candidate => candidate.EndsWith(@"node\node.exe", StringComparison.OrdinalIgnoreCase) ||
                         candidate.EndsWith(@"node\npm.cmd", StringComparison.OrdinalIgnoreCase));

        Assert.Equal("Python 3, Git", report.MissingSummary);
    }

    [Fact]
    public void Path_preamble_prepends_found_directories()
    {
        var report = ModulePrerequisites.Probe(
            @"C:\tools\node",
            candidate => candidate.EndsWith(@"node\node.exe", StringComparison.OrdinalIgnoreCase));

        var preamble = report.BuildPathPreamble();

        Assert.StartsWith("$env:PATH = 'C:\\tools\\node;' + $env:PATH", preamble, StringComparison.Ordinal);
    }

    [Fact]
    public void Path_preamble_is_empty_without_found_tools()
    {
        var report = ModulePrerequisites.Probe(null, _ => false);

        Assert.Equal(string.Empty, report.BuildPathPreamble());
    }

    [Fact]
    public void Bootstrap_script_installs_missing_packages_only()
    {
        var report = ModulePrerequisites.Probe(
            @"C:\tools\git\cmd",
            candidate => candidate.EndsWith(@"git\cmd\git.exe", StringComparison.OrdinalIgnoreCase));

        var script = ModulePrerequisites.BuildBootstrapScript(report);

        Assert.Contains("OpenJS.NodeJS.LTS", script, StringComparison.Ordinal);
        Assert.Contains("Python.Python.3.12", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Git.Git", script, StringComparison.Ordinal);
        Assert.Contains("Get-Command winget", script, StringComparison.Ordinal);
        Assert.Contains("--accept-package-agreements", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Satisfied_report_produces_no_bootstrap_commands()
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\tools\node\node.exe",
            @"C:\tools\node\npm.cmd",
            @"C:\tools\python\python.exe",
            @"C:\tools\git\cmd\git.exe",
        };

        var report = ModulePrerequisites.Probe(
            @"C:\tools\node;C:\tools\python;C:\tools\git\cmd",
            files.Contains);

        var script = ModulePrerequisites.BuildBootstrapScript(report);

        Assert.DoesNotContain("winget install", script, StringComparison.Ordinal);
    }
}
