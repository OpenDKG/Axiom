// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class ShieldProcessFilterTests
{
    [Fact]
    public void Axiom_own_install_and_module_paths_are_never_prompted()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        Assert.True(ShieldProcessFilter.IsIgnored(
            Path.Combine(local, "Programs", "Axiom", "Axiom.Desktop.exe")));
        Assert.True(ShieldProcessFilter.IsIgnored(
            Path.Combine(local, "Axiom", "modules", "blackbox", "agent-blackbox", "node.exe")));

        // Program Files exists only on Windows (the folder paths are empty elsewhere).
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.True(ShieldProcessFilter.IsIgnored(
            Path.Combine(programFiles, "Axiom", "Service", "Axiom.Service.exe")));
        Assert.True(ShieldProcessFilter.IsIgnored(
            Path.Combine(programFilesX86, "Axiom", "Axiom.Desktop.exe")));
    }

    [Fact]
    public void Linux_package_bundle_and_daemon_image_are_never_prompted()
    {
        Assert.True(ShieldProcessFilter.IsLinuxOwnPath("/usr/lib/axiom-firewall/Axiom.Desktop.Avalonia.Linux"));
        Assert.True(ShieldProcessFilter.IsLinuxOwnPath("/usr/lib/axiom-firewall/axiomd/axiomd"));
        Assert.True(ShieldProcessFilter.IsLinuxOwnPath("/usr/libexec/axiom/axiomd"));
        Assert.False(ShieldProcessFilter.IsLinuxOwnPath("/usr/lib/axiom-firewall-other/agent"));
        Assert.False(ShieldProcessFilter.IsLinuxOwnPath("/usr/lib/Axiom-Firewall/agent"));
        Assert.False(ShieldProcessFilter.IsLinuxOwnPath("/opt/axiom/agent"));
        Assert.False(ShieldProcessFilter.IsLinuxOwnPath("/usr/bin/curl"));

        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        Assert.True(ShieldProcessFilter.IsIgnored("/usr/lib/axiom-firewall/axiomd/axiomd"));
        Assert.True(ShieldProcessFilter.IsIgnored("/usr/libexec/axiom/axiomd"));
        Assert.False(ShieldProcessFilter.IsIgnored("/usr/bin/curl"));
        Assert.False(ShieldProcessFilter.IsIgnored("/usr/lib/axiom-firewall-other/agent"));
    }

    [Fact]
    public void Unrelated_user_paths_are_still_asked_about()
    {
        // Do not derive this from LocalApplicationData: on CI the workspace itself can live under
        // %LOCALAPPDATA%\Axiom, which would make the path legitimately trusted.
        Assert.False(ShieldProcessFilter.IsIgnored(@"C:\UnrelatedVendor\agent.exe"));
        Assert.False(ShieldProcessFilter.IsIgnored(null));
        Assert.False(ShieldProcessFilter.IsIgnored(string.Empty));
    }

    [Fact]
    public void MacOS_daemon_app_bundle_and_filter_extension_are_never_prompted()
    {
        // The root daemon copy launchd runs (PrivilegedHelperLayout.DaemonPath on the Mac).
        Assert.True(ShieldProcessFilter.IsMacOwnPath("/Library/PrivilegedHelperTools/com.axiom.service/axiomd", null));
        // The installed bundle, also when another copy of the app is the one running.
        Assert.True(ShieldProcessFilter.IsMacOwnPath("/Applications/Axiom.app/Contents/MacOS/Axiom", null));
        Assert.True(ShieldProcessFilter.IsMacOwnPath("/Applications/Axiom.app/Contents/Resources/service/axiomd", null));
        // The running bundle wherever it lives.
        Assert.True(ShieldProcessFilter.IsMacOwnPath("/Users/a/Downloads/Axiom.app/Contents/MacOS/Axiom", "/Users/a/Downloads/Axiom.app"));
        // The activated content-filter system extension.
        Assert.True(ShieldProcessFilter.IsMacOwnPath(
            "/Library/SystemExtensions/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0/com.axiom.firewall.filter.systemextension/Contents/MacOS/com.axiom.firewall.filter",
            null));

        Assert.False(ShieldProcessFilter.IsMacOwnPath("/Library/PrivilegedHelperTools/com.other.helper/tool", null));
        Assert.False(ShieldProcessFilter.IsMacOwnPath("/Library/PrivilegedHelperTools/com.axiom.service.evil/axiomd", null));
        Assert.False(ShieldProcessFilter.IsMacOwnPath("/Applications/Axiom.app.evil/Contents/MacOS/x", null));
        Assert.False(ShieldProcessFilter.IsMacOwnPath("/Applications/AxiomHelper.app/Contents/MacOS/x", null));
        Assert.False(ShieldProcessFilter.IsMacOwnPath("/Users/a/com.axiom.firewall.filter.systemextension/Contents/MacOS/x", null));
        Assert.False(ShieldProcessFilter.IsMacOwnPath("/Library/SystemExtensions/X/com.other.filter.systemextension/Contents/MacOS/x", null));
        Assert.False(ShieldProcessFilter.IsMacOwnPath("/usr/local/bin/curl", null));
    }

    [Fact]
    public void Critical_system_processes_cannot_be_blocked()
    {
        Assert.True(ShieldProcessFilter.IsCriticalSystemProcess("svchost.exe", @"C:\Windows\System32\svchost.exe"));
        Assert.True(ShieldProcessFilter.IsCriticalSystemProcess("lsass", @"C:\Windows\System32\lsass.exe"));
        Assert.True(ShieldProcessFilter.IsCriticalSystemProcess("System", null));
        Assert.True(ShieldProcessFilter.IsCriticalSystemProcess("launchd", "/sbin/launchd"));
        Assert.False(ShieldProcessFilter.IsCriticalSystemProcess("curl.exe", @"C:\Tools\curl.exe"));
    }

    [Fact]
    public void Process_termination_target_rejects_mismatched_identity_or_invalid_pid()
    {
        var current = System.Diagnostics.Process.GetCurrentProcess();
        var captured = Assert.Single(Axiom.Presentation.ProcessTerminationTarget.Capture([current.Id], current.MainModule?.FileName));
        Assert.True(Axiom.Presentation.ProcessTerminationTarget.MatchesLiveProcess(current, captured));

        var wrongStart = captured with { StartTimeUtc = captured.StartTimeUtc!.Value.AddMinutes(-5) };
        Assert.False(Axiom.Presentation.ProcessTerminationTarget.MatchesLiveProcess(current, wrongStart));

        var wrongPath = captured with { ExpectedPath = @"C:\nonexistent\other.exe" };
        Assert.False(Axiom.Presentation.ProcessTerminationTarget.MatchesLiveProcess(current, wrongPath));

        Assert.Empty(Axiom.Presentation.ProcessTerminationTarget.Capture([0]));
    }
}
