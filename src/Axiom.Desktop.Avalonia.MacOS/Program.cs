// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Axiom.Contracts;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

internal static class Program
{
    /// <summary>Set to <c>software</c>, <c>opengl</c> or <c>metal</c> to force a renderer.</summary>
    public const string RenderingVariable = "AXIOM_RENDERING";

    [STAThread]
    public static int Main(string[] args)
    {
        DistributionContext.ConfigureForProcess(false);
        try
        {
            if (UnixAgentSetup.TryHandle(args, out var setupExitCode))
            {
                return setupExitCode;
            }

            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception exception)
        {
            // Leave a trace for a crash before the window exists (Finder launches have no console).
            StartupLog.Write("fatal", exception);
            throw;
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new AvaloniaNativePlatformOptions
            {
                RenderingMode = RenderingModes(Environment.GetEnvironmentVariable(RenderingVariable)),
            })
            .With(new MacOSPlatformOptions
            {
                ShowInDock = true,
            })
            .LogToTrace();

    /// <summary>
    /// GPU first, then the software framebuffer. Virtual machines without a GPU (the QEMU test VM)
    /// fall through to <see cref="AvaloniaNativeRenderingMode.Software"/>.
    /// </summary>
    internal static AvaloniaNativeRenderingMode[] RenderingModes(string? overrideValue) =>
        overrideValue?.Trim().ToUpperInvariant() switch
        {
            "SOFTWARE" => [AvaloniaNativeRenderingMode.Software],
            "OPENGL" => [AvaloniaNativeRenderingMode.OpenGl, AvaloniaNativeRenderingMode.Software],
            "METAL" => [AvaloniaNativeRenderingMode.Metal, AvaloniaNativeRenderingMode.Software],
            _ =>
            [
                AvaloniaNativeRenderingMode.Metal,
                AvaloniaNativeRenderingMode.OpenGl,
                AvaloniaNativeRenderingMode.Software,
            ],
        };
}
