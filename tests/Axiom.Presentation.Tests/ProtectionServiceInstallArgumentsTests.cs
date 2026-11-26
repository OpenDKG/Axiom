// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ProtectionServiceInstallArgumentsTests
{
    [Fact]
    public void Elevated_install_carries_the_non_elevated_caller_sid()
    {
        Assert.Equal(
            "--install-service --allowed-sid S-1-5-21-1111111111-2222222222-3333333333-1001",
            ProtectionServiceInstall.WindowsInstallArguments(" S-1-5-21-1111111111-2222222222-3333333333-1001 "));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("S-1-5-21-1001 --uninstall-service")]
    [InlineData("\"S-1-5-18\"")]
    public void Missing_or_malformed_sid_is_never_passed_through(string? sid)
    {
        Assert.Equal("--install-service", ProtectionServiceInstall.WindowsInstallArguments(sid));
    }

    [Fact]
    public void Current_user_sid_is_available_on_windows_only()
    {
        var sid = ProtectionServiceInstall.CurrentUserSid();
        if (OperatingSystem.IsWindows())
        {
            Assert.StartsWith("S-1-", sid, StringComparison.Ordinal);
        }
        else
        {
            Assert.Null(sid);
        }
    }
}
