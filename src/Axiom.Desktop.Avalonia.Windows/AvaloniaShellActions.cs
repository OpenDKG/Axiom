// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>Restart and shutdown are host actions; the portable page only requests them.</summary>
public sealed class AvaloniaShellActions(Action shutdown, Action? prepareRestart = null) : IShellActions
{
    public void Restart()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            return;
        }

        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
        };
        foreach (var argument in Environment.GetCommandLineArgs().Skip(1))
        {
            startInfo.ArgumentList.Add(argument);
        }

        // Release the single-instance mutex before spawning the replacement process so it does not
        // collide with this dying instance, signal it, and exit without starting.
        prepareRestart?.Invoke();
        using var started = Process.Start(startInfo);
        shutdown();
    }

    public void Shutdown() => shutdown();
}
