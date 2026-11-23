// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Axiom.Contracts;
using Axiom.Infrastructure.Windows;

namespace Axiom.Desktop.Avalonia.Windows;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
            WriteCrashLog("unhandled", eventArgs.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, eventArgs) =>
        {
            WriteCrashLog("unobserved-task", eventArgs.Exception);
            eventArgs.SetObserved();
        };

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
        catch (Exception exception)
        {
            WriteCrashLog("fatal", exception);
            throw;
        }
        finally
        {
            App.SingleInstance = null;
        }
    }

    internal static void WriteCrashLog(string kind, Exception? exception)
    {
        if (exception is null)
        {
            return;
        }

        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Axiom",
                "logs");
            Directory.CreateDirectory(directory);
            var line = string.Create(
                CultureInfo.InvariantCulture,
                $"[{DateTimeOffset.UtcNow:O}] [{kind}] {exception}{Environment.NewLine}");
            File.AppendAllText(Path.Combine(directory, "crash.log"), line);
        }
#pragma warning disable CA1031 // Crash logging must never throw.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
