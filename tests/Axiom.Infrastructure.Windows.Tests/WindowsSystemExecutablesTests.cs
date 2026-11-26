// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Windows.Network;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class WindowsSystemExecutablesTests
{
    [Fact]
    public void PowerShell_resolves_to_the_system32_copy_not_a_path_search()
    {
        var expected = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

        Assert.True(Path.IsPathFullyQualified(WindowsSystemExecutables.PowerShell));
        Assert.Equal(expected, WindowsSystemExecutables.PowerShell, ignoreCase: true);
        Assert.True(File.Exists(WindowsSystemExecutables.PowerShell));
    }

    [Theory]
    [InlineData("..\\evil.exe")]
    [InlineData("C:\\tools\\ipconfig.exe")]
    [InlineData("")]
    public void System32_accepts_only_a_bare_file_name(string fileName)
    {
        Assert.ThrowsAny<ArgumentException>(() => WindowsSystemExecutables.System32(fileName));
    }

    [Fact]
    public void Dns_recovery_starts_powershell_and_ipconfig_by_absolute_path()
    {
        var powerShell = WindowsDnsRecoveryAdapter.CreatePowerShellStart("Get-Date");
        var flush = WindowsDnsRecoveryAdapter.CreateFlushDnsStart();

        Assert.Equal(WindowsSystemExecutables.PowerShell, powerShell.FileName, ignoreCase: true);
        Assert.False(powerShell.UseShellExecute);
        Assert.Equal(["-NoProfile", "-NonInteractive", "-Command", "Get-Date"], powerShell.ArgumentList);
        Assert.Equal(Path.Combine(Environment.SystemDirectory, "ipconfig.exe"), flush.FileName, ignoreCase: true);
        Assert.Equal("/flushdns", flush.Arguments);
    }
}
