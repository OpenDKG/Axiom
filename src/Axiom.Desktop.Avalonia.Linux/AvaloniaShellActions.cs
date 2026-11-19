// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>
/// Restart and shutdown are host actions. A restart relaunches the executable after a short delay
/// so the new process does not meet this one's single-instance lock.
/// </summary>
public sealed class AvaloniaShellActions(Action shutdown) : IShellActions
{
    public void Restart()
    {
        var command = BuildRelaunchCommand(Environment.ProcessPath, Environment.GetCommandLineArgs().Skip(1).ToArray());
        if (command is null)
        {
            return;
        }

        var startInfo = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, CreateNoWindow = true };
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(command);
        Process.Start(startInfo)?.Dispose();
        shutdown();
    }

    public void Shutdown() => shutdown();

    /// <summary>Shell command that waits, then starts a fresh detached copy of the executable.</summary>
    internal static string? BuildRelaunchCommand(string? executablePath, IReadOnlyList<string> arguments)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return null;
        }

        var launch = string.Join(' ', new[] { executablePath }.Concat(arguments).Select(MacElevation.ShellQuote));
        return "sleep 2; " + launch + " >/dev/null 2>&1 &";
    }
}
