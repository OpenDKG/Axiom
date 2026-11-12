// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Axiom.Contracts;

namespace Axiom.Desktop.Avalonia.Linux;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        DistributionContext.ConfigureForProcess(false);
        try
        {
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception exception)
        {
            // Leave a trace for a crash before the window exists (a launcher start has no console).
            StartupLog.Write("fatal", exception);
            throw;
        }
    }

    /// <summary>
    /// X11 and Wayland through Avalonia's platform detection (X11 is used under XWayland until the
    /// Wayland backend ships). The freedesktop backend also supplies the portal colour scheme and
    /// the StatusNotifierItem tray.
    /// </summary>
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new X11PlatformOptions
            {
                // The daemon runs the privileged work; the desktop should work on a bare VM framebuffer too.
                RenderingMode = [X11RenderingMode.Glx, X11RenderingMode.Software],
                WmClass = LinuxPaths.AppId,
            })
            .LogToTrace();
}
