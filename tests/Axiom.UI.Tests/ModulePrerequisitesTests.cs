// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Contracts.Modules;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class ModulePrerequisitesTests
{
    private static string? Python312(string path) =>
        path.EndsWith("python.exe", StringComparison.OrdinalIgnoreCase) ? "3.12" : null;

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
            files.Contains,
            Python312);

        Assert.True(report.IsSatisfied);
        Assert.Empty(report.Missing);
        Assert.Contains(report.SearchDirectories, directory => directory.Equals(@"C:\tools\node", StringComparison.OrdinalIgnoreCase));
        var python = Assert.Single(report.Tools, tool => tool.Tool == ModuleTool.Python);
        Assert.Equal("3.12", python.Version);
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
            candidate => candidate.StartsWith(storeAliases, StringComparison.OrdinalIgnoreCase),
            Python312);

        var python = Assert.Single(report.Tools, tool => tool.Tool == ModuleTool.Python);
        Assert.False(python.IsAvailable);
    }

    [Fact]
    public void Python_315_is_rejected_and_reported()
    {
        var report = ModulePrerequisites.Probe(
            @"C:\Users\me\AppData\Local\Python\pythoncore-3.15-64",
            candidate => candidate.EndsWith(@"pythoncore-3.15-64\python.exe", StringComparison.OrdinalIgnoreCase),
            _ => "3.15");

        var python = Assert.Single(report.Tools, tool => tool.Tool == ModuleTool.Python);
        Assert.False(python.IsAvailable);
        Assert.Contains(report.RejectedPythonVersions, version => version == "3.15");
        Assert.Contains(ModuleTool.Python, report.Missing.Select(tool => tool.Tool));
    }

    [Fact]
    public void Compatible_python_wins_over_an_incompatible_one()
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Python315\python.exe",
            @"C:\Python312\python.exe",
        };

        var report = ModulePrerequisites.Probe(
            @"C:\Python315;C:\Python312",
            files.Contains,
            candidate => candidate.Contains("315", StringComparison.Ordinal) ? "3.15" : "3.12");

        var python = Assert.Single(report.Tools, tool => tool.Tool == ModuleTool.Python);
        Assert.True(python.IsAvailable);
        Assert.Equal(@"C:\Python312", python.Directory);
        Assert.Equal("3.12", python.Version);
        Assert.Contains("3.15", report.RejectedPythonVersions);
    }

    [Fact]
    public void Python_314_and_310_are_outside_the_supported_window()
    {
        Assert.True(ModulePrerequisites.IsSupportedPython("3.11"));
        Assert.True(ModulePrerequisites.IsSupportedPython("3.12"));
        Assert.True(ModulePrerequisites.IsSupportedPython("3.13"));
        Assert.False(ModulePrerequisites.IsSupportedPython("3.10"));
        Assert.False(ModulePrerequisites.IsSupportedPython("3.14"));
        Assert.False(ModulePrerequisites.IsSupportedPython("3.15"));
        Assert.False(ModulePrerequisites.IsSupportedPython(null));
    }

    [Fact]
    public void Well_known_install_folder_is_used_when_path_is_stale()
    {
        // A desktop process keeps the PATH it started with, so a tool installed afterwards is only
        // visible through the default install folder.
        var report = ModulePrerequisites.Probe(
            null,
            candidate => candidate.EndsWith(@"Programs\nodejs\node.exe", StringComparison.OrdinalIgnoreCase),
            Python312);

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
                         candidate.EndsWith(@"node\npm.cmd", StringComparison.OrdinalIgnoreCase),
            Python312);

        Assert.Equal("Python 3.11-3.13, Git", report.MissingSummary);
    }

    [Fact]
    public void Path_preamble_puts_the_compatible_python_first()
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\tools\node\node.exe",
            @"C:\tools\python\python.exe",
        };

        var report = ModulePrerequisites.Probe(
            @"C:\tools\node;C:\tools\python",
            files.Contains,
            Python312);

        var preamble = report.BuildPathPreamble();

        Assert.StartsWith("$env:PATH = 'C:\\tools\\python;C:\\tools\\node;' + $env:PATH", preamble, StringComparison.Ordinal);
    }

    [Fact]
    public void Path_preamble_is_empty_without_found_tools()
    {
        var report = ModulePrerequisites.Probe(null, _ => false, Python312);

        Assert.Equal(string.Empty, report.BuildPathPreamble());
    }

    [Fact]
    public void Bootstrap_script_installs_missing_packages_only()
    {
        var report = ModulePrerequisites.Probe(
            @"C:\tools\git\cmd",
            candidate => candidate.EndsWith(@"git\cmd\git.exe", StringComparison.OrdinalIgnoreCase),
            Python312);

        var script = ModulePrerequisites.BuildBootstrapScript(report);

        Assert.Contains("OpenJS.NodeJS.LTS", script, StringComparison.Ordinal);
        Assert.Contains("Python.Python.3.12", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Git.Git", script, StringComparison.Ordinal);
        Assert.Contains("Get-Command winget", script, StringComparison.Ordinal);
        Assert.Contains("--accept-package-agreements", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Incompatible_python_triggers_the_312_install()
    {
        var report = ModulePrerequisites.Probe(
            @"C:\Python315",
            candidate => candidate.EndsWith(@"Python315\python.exe", StringComparison.OrdinalIgnoreCase),
            _ => "3.15");

        var script = ModulePrerequisites.BuildBootstrapScript(report);

        Assert.Contains("Python.Python.3.12", script, StringComparison.Ordinal);
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
            files.Contains,
            Python312);

        var script = ModulePrerequisites.BuildBootstrapScript(report);

        Assert.DoesNotContain("winget install", script, StringComparison.Ordinal);
    }
}
