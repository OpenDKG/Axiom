// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>Restart and shutdown are host actions; the portable page only requests them.</summary>
public sealed class AvaloniaShellActions(Action shutdown) : IShellActions
{
    public void Restart()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            return;
        }

        var arguments = Environment.GetCommandLineArgs()
            .Skip(1)
            .Select(QuoteArgument);
        Process.Start(new ProcessStartInfo(executable, string.Join(' ', arguments))
        {
            UseShellExecute = true,
        });
        shutdown();
    }

    public void Shutdown() => shutdown();

    private static string QuoteArgument(string value) =>
        $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\"";
}
