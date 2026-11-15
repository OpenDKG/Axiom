// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class OptionalModuleInstallerTests
{
    [Fact]
    public void Blackbox_script_checks_vcpp_runtime_before_choosing_oxigraph_backend()
    {
        var installer = new OptionalModuleInstaller();
        var build = typeof(OptionalModuleInstaller).GetMethod(
            "BuildBlackboxScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var script = (string)build.Invoke(installer, null)!;

        Assert.Contains("vcruntime140.dll", script, StringComparison.Ordinal);
        Assert.Contains("msvcp140.dll", script, StringComparison.Ordinal);
        Assert.Contains("oxigraph-worker", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Store_backend_defaults_to_oxigraph_worker_when_vcpp_runtime_is_absent()
    {
        Assert.Equal("oxigraph", OptionalModuleInstaller.SelectBlackboxStoreBackend(hasVcRuntime: true));
        Assert.Equal("oxigraph-worker", OptionalModuleInstaller.SelectBlackboxStoreBackend(hasVcRuntime: false));
    }

    [Fact]
    public void PowerShell_resolution_prefers_pwsh_7_over_windows_powershell()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string pwshInPath = @"C:\Tools\pwsh\pwsh.exe";
        Assert.Equal(
            pwshInPath,
            OptionalModuleInstaller.ResolvePowerShellExecutable(
                pathVariable: @"C:\Tools\pwsh;C:\Windows\System32\WindowsPowerShell\v1.0",
                fileExists: p => string.Equals(p, pwshInPath, StringComparison.OrdinalIgnoreCase),
                programFiles: @"C:\Program Files"));

        const string standardPwsh = @"C:\Program Files\PowerShell\7\pwsh.exe";
        Assert.Equal(
            standardPwsh,
            OptionalModuleInstaller.ResolvePowerShellExecutable(
                pathVariable: @"C:\Windows\System32",
                fileExists: p => string.Equals(p, standardPwsh, StringComparison.OrdinalIgnoreCase),
                programFiles: @"C:\Program Files"));

        Assert.Equal(
            "powershell.exe",
            OptionalModuleInstaller.ResolvePowerShellExecutable(
                pathVariable: @"C:\Windows\System32",
                fileExists: _ => false,
                programFiles: @"C:\Program Files"));
    }
}
