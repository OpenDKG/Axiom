// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Axiom.Contracts;
using Axiom.Infrastructure.Windows;

namespace Axiom.Desktop.Avalonia.Windows;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        DistributionContext.ConfigureForProcess(StorePackageDetector.IsPackaged);
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
