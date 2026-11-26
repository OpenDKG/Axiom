// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using Axiom.Infrastructure.Windows;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class PrivacyDnsFailSafeLaunchTests
{
    [Fact]
    public void Fail_safe_powershell_is_started_from_system32_by_absolute_path()
    {
        var start = PrivacyDnsFailSafe.CreateHiddenPowerShellStart("Write-Output 1");

        Assert.True(Path.IsPathFullyQualified(start.FileName));
        Assert.Equal(WindowsSystemExecutables.PowerShell, start.FileName, ignoreCase: true);
        Assert.StartsWith(Environment.SystemDirectory, start.FileName, StringComparison.OrdinalIgnoreCase);
        Assert.False(start.UseShellExecute);
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Output 1"));
        Assert.EndsWith($"-EncodedCommand {encoded}", start.Arguments, StringComparison.Ordinal);
    }
}
