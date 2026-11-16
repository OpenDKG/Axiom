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
    public void Startup_provisioning_does_nothing_off_windows_even_with_a_complete_profile_marker()
    {
        // POSIX-only behaviour. The Windows CI gate allows no skipped tests, so on Windows this
        // returns without asserting; it runs for real on macOS and Linux.
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Path.Combine(Path.GetTempPath(), "axiom-prov-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Axiom"));
            File.WriteAllText(Path.Combine(root, "Axiom", "install-profile.json"), "{\"profile\":\"complete\"}");

            var result = ProtectionProvisioner.ProvisionAtStartup(root);

            Assert.Null(result);
            Assert.False(File.Exists(Path.Combine(root, "Axiom", "protection-status.json")));
            Assert.False(Directory.Exists(Path.Combine(root, "hermes")));
            Assert.Equal(
                [Path.Combine(root, "Axiom", "install-profile.json")],
                Directory.GetFiles(root, "*", SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>Explicit platform flag: nothing is read or written for a non-Windows host on any OS.</summary>
    [Fact]
    public void Startup_provisioning_with_the_non_windows_flag_reads_and_writes_nothing()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-prov-" + Guid.NewGuid().ToString("N"));

        Assert.Null(ProtectionProvisioner.ProvisionAtStartup(root, windows: false));
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void Guard_runtime_is_claimed_on_windows_only()
    {
        Assert.True(BlackboxPlatformSupport.GuardRuntimeSupported(windows: true));
        Assert.False(BlackboxPlatformSupport.GuardRuntimeSupported(windows: false));
        Assert.Equal(OperatingSystem.IsWindows(), BlackboxPlatformSupport.IsGuardRuntimeSupported);
    }

    /// <summary>Windows keeps upstream's label and text; elsewhere an attached workspace is the "installed, not proven" state.</summary>
    [Fact]
    public void An_attached_workspace_is_protected_only_where_the_guard_runtime_is_verified()
    {
        Assert.Equal("PROTECTED", BlackboxPlatformSupport.AttachedWorkspaceStatus(windows: true));
        Assert.Equal("Workspace attached", BlackboxPlatformSupport.AttachedWorkspaceDetail(windows: true, "Windows"));

        Assert.Equal("HOOK INSTALLED", BlackboxPlatformSupport.AttachedWorkspaceStatus(windows: false));
        var detail = BlackboxPlatformSupport.AttachedWorkspaceDetail(windows: false, "macOS");
        Assert.Contains("not verified on macOS", detail, StringComparison.Ordinal);
        Assert.Contains("not shown as protected", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Status_text_names_every_unsupported_part_off_windows_and_is_untouched_on_windows()
    {
        const string text = "Blackbox dashboard is offline; local guard and cached ruleset remain active for hooked agents.";

        Assert.Equal(text, BlackboxPlatformSupport.WithUnsupportedNote(text, windows: true, "Windows"));
        Assert.Equal(string.Empty, BlackboxPlatformSupport.UnsupportedNote(windows: true, "Windows"));

        var noted = BlackboxPlatformSupport.WithUnsupportedNote(text, windows: false, "macOS");
        Assert.StartsWith(text + " On macOS ", noted, StringComparison.Ordinal);
        foreach (var part in new[]
                 {
                     "guard runtime", "full-install provisioning", "Trader Shield", "protected-path checks",
                     "prompt-injection quarantine", "post-install self-test", "unsupported and unverified",
                     "a hooked or attached workspace is not protection",
                 })
        {
            Assert.Contains(part, noted, StringComparison.Ordinal);
        }

        Assert.Equal(
            BlackboxPlatformSupport.UnsupportedNote(windows: false, "Linux"),
            BlackboxPlatformSupport.WithUnsupportedNote(string.Empty, windows: false, "Linux"));
    }

    /// <summary>
    /// Shared Avalonia files that name a provisioning entry point but reach it only behind an
    /// <c>OperatingSystem.IsWindows()</c> gate. Each needs a behaviour test proving nothing runs
    /// off Windows: TraderShieldSectionViewModel (upstream v0.5x) is covered by
    /// <c>TraderShieldSectionViewModelTests.Off_windows_the_default_section_reads_and_writes_nothing</c>.
    /// </summary>
    private static readonly string[] RuntimeGatedSharedFiles = ["TraderShieldSectionViewModel.cs"];

    /// <summary>
    /// The macOS desktop host and the shared Avalonia UI never call the Windows provisioning entry
    /// points or the process-window hider; only Axiom.Desktop.Avalonia.Windows does (plus the
    /// runtime-gated files listed in <see cref="RuntimeGatedSharedFiles"/>).
    /// </summary>
    [Fact]
    public void Mac_host_and_shared_avalonia_ui_do_not_call_windows_provisioning()
    {
        var repo = AppContext.BaseDirectory;
        while (repo is not null && !File.Exists(Path.Combine(repo, "Axiom.sln")))
        {
            repo = Path.GetDirectoryName(repo);
        }

        Assert.NotNull(repo);
        string[] forbidden =
        [
            "ProtectionProvisioner.", "PrivacyShieldProvisioner.", "TraderShieldProvisioner.",
            "HermesPluginSettings.", "ModuleWindowHider", "AxiomModuleProcessMatcher.",
        ];
        var hits = NonWindowsHostProjects
            .Select(project => Path.Combine(repo!, "src", project))
            .Where(Directory.Exists)
            .SelectMany(directory => Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories))
            .Where(file => !file.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !file.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !RuntimeGatedSharedFiles.Contains(Path.GetFileName(file)))
            .SelectMany(file => forbidden
                .Where(name => File.ReadAllText(file).Contains(name, StringComparison.Ordinal))
                .Select(name => $"{Path.GetFileName(file)}: {name}"))
            .ToList();

        Assert.Empty(hits);
    }
}
