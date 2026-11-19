// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Axiom.Contracts.Blackbox;
using Axiom.UI.ViewModels;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class LifecycleAndSetupRegressionTests
{
    private static readonly string[] EmptyInstallDirArgs = ["--install-dir", "   "];
    [Fact]
    public void Wpf_agents_merge_activity_caps_retained_entries_at_activity_max()
    {
        using var security = new SecurityViewModel();
        using var agents = new AgentsViewModel(security);

        var apply = typeof(AgentsViewModel).GetMethod("ApplyActivity", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var merge = typeof(AgentsViewModel).GetMethod("MergeActivity", BindingFlags.Instance | BindingFlags.NonPublic)!;

        var initial = Enumerable.Range(0, 19_990)
            .Select(i => new BlackboxAuditEntry(
                DateTimeOffset.UtcNow.AddSeconds(-i),
                "pre_tool_call",
                "Codex",
                $"sess-{i}",
                "bash",
                $"echo {i}",
                "allow",
                "info",
                $"id-{i}",
                $"detail-{i}"))
            .ToList();
        apply.Invoke(agents, [new BlackboxAuditPage(initial, initial.Count)]);
        Assert.Equal(19_990, agents.Activity.Count);

        var added = Enumerable.Range(19_990, 50)
            .Select(i => new BlackboxAuditEntry(
                DateTimeOffset.UtcNow.AddSeconds(-i),
                "pre_tool_call",
                "Codex",
                $"sess-{i}",
                "bash",
                $"echo {i}",
                "allow",
                "info",
                $"id-{i}",
                $"detail-{i}"))
            .ToList();
        merge.Invoke(agents, [new BlackboxAuditPage(added, 20_040)]);

        Assert.Equal(20_000, agents.Activity.Count);
    }

    [Fact]
    public void Setup_options_and_service_query_name_handle_edge_cases()
    {
        var setupAssemblyPath = Path.Combine(
            FindRepoRoot(),
            "src",
            "Axiom.Setup",
            "bin",
            "Debug",
            "net10.0-windows",
            "Axiom.Setup.dll");
        if (!File.Exists(setupAssemblyPath))
        {
            return;
        }

        var setupAssembly = Assembly.LoadFrom(setupAssemblyPath);
        var optionsType = setupAssembly.GetType("Axiom.Setup.SetupOptions", throwOnError: true)!;
        var parse = optionsType.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var customDir = Path.Combine(Path.GetTempPath(), "axiom-setup-test-dir");
        var equalsParsed = parse.Invoke(null, [new[] { $"--install-dir={customDir}", "--silent", "--no-launch" }])!;
        Assert.Equal(Path.GetFullPath(customDir), optionsType.GetProperty("InstallDir")!.GetValue(equalsParsed));
        Assert.True((bool)optionsType.GetProperty("Silent")!.GetValue(equalsParsed)!);
        Assert.False((bool)optionsType.GetProperty("StartAfterInstall")!.GetValue(equalsParsed)!);

        // Empty or invalid --install-dir values must fall back cleanly instead of throwing ArgumentException.
        var emptyParsed = parse.Invoke(null, [EmptyInstallDirArgs])!;
        Assert.False(string.IsNullOrWhiteSpace((string)optionsType.GetProperty("InstallDir")!.GetValue(emptyParsed)!));

        var installerType = setupAssembly.GetType("Axiom.Setup.SetupInstaller", throwOnError: true)!;
        var queryField = installerType.GetField("WindowsServiceQueryArguments", BindingFlags.NonPublic | BindingFlags.Static)!;
        Assert.Equal("query Axiom", (string)queryField.GetValue(null)!);

        var tempFile = Path.Combine(Path.GetTempPath(), $"axiom-delete-retry-{Guid.NewGuid():N}.tmp");
        File.WriteAllText(tempFile, "test");
        var deleteMethod = installerType.GetMethod("DeleteFileWithRetry", BindingFlags.NonPublic | BindingFlags.Static)!;
        deleteMethod.Invoke(null, [tempFile]);
        Assert.False(File.Exists(tempFile));
    }

    private static string FindRepoRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Axiom.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate Axiom.sln");
    }
}
