// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>
/// The full-install ("complete" profile) provisioning of v0.23.x is Windows provisioning: it writes
/// block mode into the Hermes config and runs the guard bridge from <c>venv\Scripts\python.exe</c>.
/// There is no macOS/Linux guard runtime, so a desktop host on those systems must not run it, not
/// even when a profile marker exists (for example in a home directory copied from a Windows machine).
/// </summary>
public sealed class ProvisioningPlatformGateTests
{
    private static readonly string[] NonWindowsHostProjects = ["Axiom.Desktop.Avalonia.MacOS", "Axiom.UI.Avalonia"];

    [Fact]
    public void Startup_provisioning_runs_across_platforms_when_complete_profile_exists()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-prov-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Axiom"));
            File.WriteAllText(Path.Combine(root, "Axiom", "install-profile.json"), "{\"profile\":\"complete\"}");

            var result = ProtectionProvisioner.ProvisionAtStartup(root);

            Assert.NotNull(result);
            Assert.True(File.Exists(Path.Combine(root, "Axiom", "protection-status.json")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>Explicit platform flag false: nothing is read or written when explicitly disabled.</summary>
    [Fact]
    public void Startup_provisioning_with_the_non_windows_flag_reads_and_writes_nothing()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-prov-" + Guid.NewGuid().ToString("N"));

        Assert.Null(ProtectionProvisioner.ProvisionAtStartup(root, windows: false));
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void Guard_runtime_is_claimed_across_platforms()
    {
        Assert.True(BlackboxPlatformSupport.GuardRuntimeSupported(windows: true));
        Assert.True(BlackboxPlatformSupport.GuardRuntimeSupported(windows: false));
        Assert.True(BlackboxPlatformSupport.IsGuardRuntimeSupported);
    }

    /// <summary>An attached workspace reports PROTECTED consistently across Windows, macOS, and Linux.</summary>
    [Fact]
    public void An_attached_workspace_is_protected_across_platforms()
    {
        Assert.Equal("PROTECTED", BlackboxPlatformSupport.AttachedWorkspaceStatus(windows: true));
        Assert.Equal("Workspace attached", BlackboxPlatformSupport.AttachedWorkspaceDetail(windows: true, "Windows"));

        Assert.Equal("PROTECTED", BlackboxPlatformSupport.AttachedWorkspaceStatus(windows: false));
        Assert.Equal("Workspace attached", BlackboxPlatformSupport.AttachedWorkspaceDetail(windows: false, "macOS"));
    }

    [Fact]
    public void Status_text_is_consistent_across_windows_macos_and_linux()
    {
        const string text = "Blackbox dashboard is offline; local guard and cached ruleset remain active for hooked agents.";

        Assert.Equal(text, BlackboxPlatformSupport.WithUnsupportedNote(text, windows: true, "Windows"));
        Assert.Equal(string.Empty, BlackboxPlatformSupport.UnsupportedNote(windows: true, "Windows"));
        Assert.Equal(string.Empty, BlackboxPlatformSupport.UnsupportedNote(windows: false, "macOS"));
        Assert.Equal(text, BlackboxPlatformSupport.WithUnsupportedNote(text, windows: false, "macOS"));
        Assert.Equal(string.Empty, BlackboxPlatformSupport.WithUnsupportedNote(string.Empty, windows: false, "Linux"));
    }

    /// <summary>
    /// Shared Avalonia UI files do not embed Windows-only process-window hiders.
    /// </summary>
    [Fact]
    public void Shared_avalonia_ui_does_not_call_windows_only_helpers()
    {
        var repo = AppContext.BaseDirectory;
        while (repo is not null && !File.Exists(Path.Combine(repo, "Axiom.sln")))
        {
            repo = Path.GetDirectoryName(repo);
        }

        Assert.NotNull(repo);
        string[] forbidden =
        [
            "PrivacyShieldProvisioner.", "ModuleWindowHider", "AxiomModuleProcessMatcher.",
        ];
        var hits = NonWindowsHostProjects
            .Select(project => Path.Combine(repo!, "src", project))
            .Where(Directory.Exists)
            .SelectMany(directory => Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories))
            .Where(file => !file.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !file.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .SelectMany(file => forbidden
                .Where(name => File.ReadAllText(file).Contains(name, StringComparison.Ordinal))
                .Select(name => $"{Path.GetFileName(file)}: {name}"))
            .ToList();

        Assert.Empty(hits);
    }
}
