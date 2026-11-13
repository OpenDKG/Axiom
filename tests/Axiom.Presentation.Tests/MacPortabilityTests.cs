// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class MacElevationTests
{
    [Fact]
    public void Shell_quote_survives_single_quotes_and_spaces()
    {
        Assert.Equal("'/Applications/My App.app'", MacElevation.ShellQuote("/Applications/My App.app"));
        Assert.Equal("'it'\\''s'", MacElevation.ShellQuote("it's"));
    }

    [Fact]
    public void AppleScript_string_escapes_quotes_backslashes_and_newlines()
    {
        Assert.Equal("\"a\\\\b \\\"c\\\" d\"", MacElevation.AppleScriptString("a\\b \"c\"\nd"));
    }

    [Fact]
    public void Do_shell_script_statement_is_built_from_quoted_parts()
    {
        var command = MacElevation.BuildShellCommand(
            "/Applications/Ax\"iom.app/Contents/Resources/service/axiomd",
            "--install-service");
        Assert.Equal(
            "'/Applications/Ax\"iom.app/Contents/Resources/service/axiomd' '--install-service'",
            command);

        var script = MacElevation.BuildAppleScript(command, "Axiom wants to install");
        Assert.Equal(
            "do shell script \"'/Applications/Ax\\\"iom.app/Contents/Resources/service/axiomd' '--install-service'\"" +
            " with prompt \"Axiom wants to install\" with administrator privileges",
            script);
    }

    [Fact]
    public void Cancelled_dialog_is_detected()
    {
        Assert.True(new MacElevationResult(1, string.Empty, "execution error: User canceled. (-128)").Cancelled);
        Assert.False(new MacElevationResult(1, string.Empty, "other").Cancelled);
    }
}

public sealed class MacBundleLayoutTests
{
    [UnixOnlyFact]
    public void Paths_inside_an_installed_bundle()
    {
        var layout = new MacBundleLayout("/Applications/Axiom.app/Contents/MacOS/");

        Assert.True(layout.IsInsideAppBundle);
        Assert.True(layout.IsInApplicationsFolder);
        Assert.Equal("/Applications/Axiom.app", layout.BundlePath);

        // The layout joins with Path.Combine, so the leaf separators follow the host OS: a Windows
        // runner sees "/Applications/Axiom.app/Contents\Resources\service\axiomd". The bundle root
        // itself is only ever split with Path.GetDirectoryName, which keeps the '/' it was given.
        Assert.Equal(Path.Combine("/Applications/Axiom.app/Contents", "Resources", "service", "axiomd"), layout.DaemonPath);
        Assert.Equal(Path.Combine("/Applications/Axiom.app/Contents/MacOS", "axiom-sysext"), layout.SysextHelperPath);
    }

    [Fact]
    public void A_bundle_outside_applications_and_a_plain_folder()
    {
        var downloads = new MacBundleLayout("/Users/me/Downloads/Axiom.app/Contents/MacOS");
        Assert.True(downloads.IsInsideAppBundle);
        Assert.False(downloads.IsInApplicationsFolder);

        var plain = new MacBundleLayout("/tmp/publish");
        Assert.False(plain.IsInsideAppBundle);
        Assert.Null(plain.BundlePath);
        Assert.Equal(Path.Combine("/tmp/publish", "service", "axiomd"), plain.DaemonPath);
    }

    [Fact]
    public async Task Install_runs_axiomd_install_service_through_the_admin_prompt()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-bundle-" + Guid.NewGuid().ToString("N"), "Axiom.app");
        var macos = Path.Combine(directory, "Contents", "MacOS");
        var service = Path.Combine(directory, "Contents", "Resources", "service");
        Directory.CreateDirectory(macos);
        Directory.CreateDirectory(service);
        await File.WriteAllTextAsync(Path.Combine(service, "axiomd"), "#!/bin/sh\n");
        try
        {
            string? seen = null;
            var result = await ProtectionServiceInstall.InstallAndStartMacAsync(
                new MacBundleLayout(macos),
                (command, _, _) =>
                {
                    seen = command;
                    return Task.FromResult(new MacElevationResult(0, "Installed", string.Empty));
                },
                CancellationToken.None);

            Assert.True(result.Success);
            Assert.Equal(MacElevation.ShellQuote(Path.Combine(service, "axiomd")) + " '--install-service'", seen);

            var cancelled = await ProtectionServiceInstall.InstallAndStartMacAsync(
                new MacBundleLayout(macos),
                (_, _, _) => Task.FromResult(new MacElevationResult(1, string.Empty, "User canceled. (-128)")),
                CancellationToken.None);
            Assert.False(cancelled.Success);
            Assert.Equal("Administrator approval was cancelled.", cancelled.Message);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(directory)!, recursive: true);
        }
    }

    [Fact]
    public async Task Install_reports_a_missing_daemon_without_prompting()
    {
        var prompted = false;
        var result = await ProtectionServiceInstall.InstallAndStartMacAsync(
            new MacBundleLayout("/nonexistent/Axiom.app/Contents/MacOS"),
            (_, _, _) =>
            {
                prompted = true;
                return Task.FromResult(new MacElevationResult(0, string.Empty, string.Empty));
            },
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.False(prompted);
        Assert.Contains("axiomd", result.Message, StringComparison.Ordinal);
    }
}

public sealed class AgentPlatformTests
{
    [Fact]
    public void Windows_layout_is_unchanged()
    {
        Assert.Equal(
            Path.Combine("root", "venv", "Scripts", "python.exe"),
            AgentPlatform.VenvPython("root", windows: true));
        Assert.Equal(
            Path.Combine("root", "venv", "Scripts", "hermes.exe"),
            AgentPlatform.VenvTool("root", "hermes", windows: true));
        Assert.Equal("opencode.exe", AgentPlatform.ExecutableName("opencode", windows: true));
        Assert.Equal([".EXE", ".CMD"], AgentPlatform.PathExtensions(windows: true, ".EXE;.CMD"));
    }

    [Fact]
    public void Posix_layout_uses_bin_and_bare_names()
    {
        Assert.Equal(
            Path.Combine("root", "venv", "bin", "python"),
            AgentPlatform.VenvPython("root", windows: false));
        Assert.Equal("opencode", AgentPlatform.ExecutableName("opencode", windows: false));
        Assert.Empty(AgentPlatform.PathExtensions(windows: false, ".EXE"));
        Assert.Contains("/opt/homebrew/bin", AgentPlatform.MacExtraSearchDirectories("/Users/me"));
    }

    [Fact]
    public void Hook_scripts_keep_windows_text_and_get_posix_evidence_path_elsewhere()
    {
        var script = AgentHookScript.Build("claude");
        var windows = AgentPlatform.AdaptHookScript(script.Replace(
            AgentPlatform.PosixEvidenceRoot,
            AgentPlatform.WindowsEvidenceRoot,
            StringComparison.Ordinal), windows: true);
        Assert.Contains(AgentPlatform.WindowsEvidenceRoot, windows, StringComparison.Ordinal);

        var posix = AgentPlatform.AdaptHookScript(windows, windows: false);
        Assert.DoesNotContain(AgentPlatform.WindowsEvidenceRoot, posix, StringComparison.Ordinal);
        Assert.Contains("\"Library\" / \"Application Support\"", posix, StringComparison.Ordinal);
        Assert.Contains("sys.platform == \"darwin\"", posix, StringComparison.Ordinal);
    }

    [Fact]
    public void Script_on_this_os_matches_its_platform_rule()
    {
        var script = AgentHookScript.Build("codex");
        Assert.Contains(
            OperatingSystem.IsWindows() ? AgentPlatform.WindowsEvidenceRoot : AgentPlatform.PosixEvidenceRoot,
            script,
            StringComparison.Ordinal);
    }
}
