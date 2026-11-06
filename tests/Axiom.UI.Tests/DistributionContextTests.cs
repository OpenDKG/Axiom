// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class DistributionContextTests
{
    [Fact]
    public void Store_package_disables_hkcu_autostart()
    {
        var previous = DistributionContext.IsPackaged;
        try
        {
            DistributionContext.ConfigureForProcess(true);

            Assert.True(DistributionContext.IsStorePackage);

            var registration = new AutostartRegistration(@"C:\Axiom\Axiom.Desktop.exe");
            Assert.Equal(AutostartState.Unavailable, registration.Read().State);
            Assert.False(registration.Enable());
        }
        finally
        {
            DistributionContext.ConfigureForProcess(previous);
        }
    }

    [Fact]
    public void Store_package_blocks_optional_installers()
    {
        var previous = DistributionContext.IsPackaged;
        try
        {
            DistributionContext.ConfigureForProcess(true);
            var installer = new OptionalModuleInstaller();
            var log = new List<string>();

            Assert.False(installer.InstallDkgAndWait(log.Add));
            Assert.False(installer.InstallBlackboxAndWait(log.Add));
            Assert.False(installer.StartDkg());
            Assert.False(installer.StartBlackboxDashboard());
            Assert.Equal(2, log.Count);
        }
        finally
        {
            DistributionContext.ConfigureForProcess(previous);
        }
    }
}
