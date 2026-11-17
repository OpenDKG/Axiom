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
}
