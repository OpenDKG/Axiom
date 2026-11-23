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
    private static readonly string[] SetupBuildConfigurations = ["Release", "Debug"];
    private static readonly string[] EmptyInstallDirArgs = ["--install-dir", "   "];
    private static readonly string[] ConsentedCompleteArgs = ["--silent", "--accept-risk"];
    private static readonly string[] OptedOutCompleteArgs = ["--silent", "--accept-risk", "--no-automatic-threat-sharing"];
    private static readonly string[] ConsentedPartialArgs = ["--silent", "--accept-risk", "--partial"];
    private static readonly string[] LightModeArgs = ["--silent", "--accept-risk", "--light"];
    private static readonly string[] OptionalDefaultArgs = ["--silent", "--accept-risk", "--optional"];
    private static readonly string[] OptionalCustomArgs =
    [
        "--silent", "--accept-risk", "--optional", "--no-privacy-shield", "--with-blackbox", "--with-agent-hooks",
    ];
    private static readonly string[] UninstallPurgeArgs = ["--uninstall", "--remove-data", "--allow-downgrade"];
    private static readonly string[] ConflictingModeArgs = ["--complete", "--light"];
    private static readonly string[] ConflictingOverrideArgs = ["--light", "--with-dkg"];
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
        var setupAssemblyPath = SetupBuildConfigurations
            .Select(config => Path.Combine(FindRepoRoot(), "src", "Axiom.Setup", "bin", config, "net10.0-windows", "Axiom.Setup.dll"))
            .FirstOrDefault(File.Exists);
        if (setupAssemblyPath is null)
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
        Assert.False((bool)optionsType.GetProperty("EnableAutomaticThreatSharing")!.GetValue(equalsParsed)!);

        var consentedComplete = parse.Invoke(null, [ConsentedCompleteArgs])!;
        Assert.False((bool)optionsType.GetProperty("EnableAutomaticThreatSharing")!.GetValue(consentedComplete)!);

        var optedInComplete = parse.Invoke(null, [ConsentedCompleteArgs.Concat(["--enable-automatic-threat-sharing"]).ToArray()])!;
        Assert.True((bool)optionsType.GetProperty("EnableAutomaticThreatSharing")!.GetValue(optedInComplete)!);

        var optedOutComplete = parse.Invoke(null, [OptedOutCompleteArgs])!;
        Assert.False((bool)optionsType.GetProperty("EnableAutomaticThreatSharing")!.GetValue(optedOutComplete)!);

        var consentedPartial = parse.Invoke(null, [ConsentedPartialArgs])!;
        Assert.False((bool)optionsType.GetProperty("EnableAutomaticThreatSharing")!.GetValue(consentedPartial)!);
        Assert.Equal("Light", optionsType.GetProperty("EffectiveMode")!.GetValue(consentedPartial)!.ToString());
        Assert.True((bool)optionsType.GetProperty("EffectiveFirewallShield")!.GetValue(consentedPartial)!);
        Assert.True((bool)optionsType.GetProperty("EffectivePrivacyShield")!.GetValue(consentedPartial)!);
        Assert.True((bool)optionsType.GetProperty("EffectiveAutostartAndFeed")!.GetValue(consentedPartial)!);
        Assert.False((bool)optionsType.GetProperty("EffectiveInstallBlackbox")!.GetValue(consentedPartial)!);
        Assert.False((bool)optionsType.GetProperty("EffectiveInstallDkg")!.GetValue(consentedPartial)!);
        Assert.False((bool)optionsType.GetProperty("EffectiveInstallAgentHooks")!.GetValue(consentedPartial)!);
        Assert.True((bool)optionsType.GetProperty("RequiresWindowsService")!.GetValue(consentedPartial)!);

        var lightParsed = parse.Invoke(null, [LightModeArgs])!;
        Assert.Equal("Light", optionsType.GetProperty("EffectiveMode")!.GetValue(lightParsed)!.ToString());
        Assert.True((bool)optionsType.GetProperty("EffectiveFirewallShield")!.GetValue(lightParsed)!);
        Assert.True((bool)optionsType.GetProperty("EffectivePrivacyShield")!.GetValue(lightParsed)!);
        Assert.True((bool)optionsType.GetProperty("EffectiveAutostartAndFeed")!.GetValue(lightParsed)!);
        Assert.False((bool)optionsType.GetProperty("EffectiveInstallBlackbox")!.GetValue(lightParsed)!);

        var optionalDefault = parse.Invoke(null, [OptionalDefaultArgs])!;
        Assert.Equal("Optional", optionsType.GetProperty("EffectiveMode")!.GetValue(optionalDefault)!.ToString());
        Assert.True((bool)optionsType.GetProperty("EffectiveFirewallShield")!.GetValue(optionalDefault)!);
        Assert.True((bool)optionsType.GetProperty("EffectivePrivacyShield")!.GetValue(optionalDefault)!);
        Assert.False((bool)optionsType.GetProperty("EffectiveInstallBlackbox")!.GetValue(optionalDefault)!);

        var optionalCustom = parse.Invoke(null, [OptionalCustomArgs])!;
        Assert.Equal("Optional", optionsType.GetProperty("EffectiveMode")!.GetValue(optionalCustom)!.ToString());
        Assert.True((bool)optionsType.GetProperty("EffectiveFirewallShield")!.GetValue(optionalCustom)!);
        Assert.False((bool)optionsType.GetProperty("EffectivePrivacyShield")!.GetValue(optionalCustom)!);
        Assert.True((bool)optionsType.GetProperty("EffectiveInstallBlackbox")!.GetValue(optionalCustom)!);
        Assert.False((bool)optionsType.GetProperty("EffectiveInstallDkg")!.GetValue(optionalCustom)!);
        Assert.True((bool)optionsType.GetProperty("EffectiveInstallAgentHooks")!.GetValue(optionalCustom)!);
        Assert.False((bool)optionsType.GetProperty("EnableAutomaticThreatSharing")!.GetValue(optionalCustom)!);

        // #31 / #32 setup flags: uninstall data removal, allow downgrade, and conflict detection.
        var uninstallPurge = parse.Invoke(null, [UninstallPurgeArgs])!;
        Assert.True((bool)optionsType.GetProperty("Uninstall")!.GetValue(uninstallPurge)!);
        Assert.True((bool)optionsType.GetProperty("RemoveData")!.GetValue(uninstallPurge)!);
        Assert.True((bool)optionsType.GetProperty("AllowDowngrade")!.GetValue(uninstallPurge)!);
        Assert.Null(optionsType.GetProperty("ParseError")!.GetValue(uninstallPurge));

        var conflictingModes = parse.Invoke(null, [ConflictingModeArgs])!;
        Assert.False(string.IsNullOrWhiteSpace((string?)optionsType.GetProperty("ParseError")!.GetValue(conflictingModes)));

        var conflictingOverride = parse.Invoke(null, [ConflictingOverrideArgs])!;
        Assert.False(string.IsNullOrWhiteSpace((string?)optionsType.GetProperty("ParseError")!.GetValue(conflictingOverride)));

        var installerType = setupAssembly.GetType("Axiom.Setup.SetupInstaller", throwOnError: true)!;
        var compareVersions = installerType.GetMethod("CompareVersions", BindingFlags.NonPublic | BindingFlags.Static)!;
        Assert.True((int)compareVersions.Invoke(null, ["1.4.9", "1.4.7"])! > 0);
        Assert.Equal(0, (int)compareVersions.Invoke(null, ["1.4.9+abc", "1.4.9.0"])!);
        Assert.True((int)compareVersions.Invoke(null, ["1.4.7", "1.4.9"])! < 0);

        // Empty or invalid --install-dir values must fall back cleanly instead of throwing ArgumentException.
        var emptyParsed = parse.Invoke(null, [EmptyInstallDirArgs])!;
        Assert.False(string.IsNullOrWhiteSpace((string)optionsType.GetProperty("InstallDir")!.GetValue(emptyParsed)!));

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
