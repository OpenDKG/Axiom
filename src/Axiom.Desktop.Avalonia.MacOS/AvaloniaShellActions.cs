// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// Restart and shutdown are host actions. A restart relaunches the bundle with <c>open -n</c> after
/// a short delay so the new process does not meet this one's single-instance lock.
/// </summary>
public sealed class AvaloniaShellActions(Action shutdown) : IShellActions
{
    public void Restart()
    {
        var command = BuildRelaunchCommand(
            MacBundleLayout.Current.BundlePath,
            Environment.ProcessPath,
            Environment.GetCommandLineArgs().Skip(1).ToArray());
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

    /// <summary>Shell command that waits, then starts a fresh copy (bundle via open, else the binary).</summary>
    internal static string? BuildRelaunchCommand(string? bundlePath, string? executablePath, IReadOnlyList<string> arguments)
    {
        string launch;
        if (!string.IsNullOrWhiteSpace(bundlePath))
        {
            launch = "/usr/bin/open -n " + MacElevation.ShellQuote(bundlePath);
            if (arguments.Count > 0)
            {
                launch += " --args " + string.Join(' ', arguments.Select(MacElevation.ShellQuote));
            }
        }
        else if (!string.IsNullOrWhiteSpace(executablePath))
        {
            launch = string.Join(' ', new[] { executablePath }.Concat(arguments).Select(MacElevation.ShellQuote)) +
                     " >/dev/null 2>&1 &";
        }
        else
        {
            return null;
        }

        return "sleep 2; " + launch;
    }
}
