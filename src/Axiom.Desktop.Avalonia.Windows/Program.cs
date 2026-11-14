// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Axiom.Contracts;
using Axiom.Infrastructure.Windows;

namespace Axiom.Desktop.Avalonia.Windows;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        DistributionContext.ConfigureForProcess(StorePackageDetector.IsPackaged);

        using var instance = SingleInstanceGuard.AcquireOrSignalExisting();
        if (instance is null)
        {
            return 0;
        }

        App.SingleInstance = instance;
        try
        {
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        finally
        {
            App.SingleInstance = null;
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
