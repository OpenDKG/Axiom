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
        Assert.True(ShieldProcessFilter.IsIgnored(
            Path.Combine(programFiles, "Axiom", "Service", "Axiom.Service.exe")));
        Assert.True(ShieldProcessFilter.IsIgnored(
            Path.Combine(programFilesX86, "Axiom", "Axiom.Desktop.exe")));
    }

    [Fact]
    public void Unrelated_user_paths_are_still_asked_about()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        Assert.False(ShieldProcessFilter.IsIgnored(
            Path.Combine(local, "SomeVendor", "agent.exe")));
        Assert.False(ShieldProcessFilter.IsIgnored(null));
        Assert.False(ShieldProcessFilter.IsIgnored(string.Empty));
    }
}
