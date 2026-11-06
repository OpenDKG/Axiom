// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Infrastructure.Windows;

namespace Axiom.Desktop;

/// <summary>
/// Entry point of the real application. No service, no driver, no firewall write path and no
/// elevation. The composition root is the only assembly that references Windows adapters.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        DistributionContext.ConfigureForProcess(StorePackageDetector.IsPackaged);

        var application = new App();
        application.InitializeComponent();
        application.Run();
    }
}
