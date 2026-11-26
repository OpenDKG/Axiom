// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Windows;

/// <summary>
/// Absolute paths for Windows tools started from privileged (LocalSystem) code. A bare name such as
/// <c>powershell.exe</c> is resolved through the search path, so a writable directory on the
/// system <c>PATH</c> could supply the binary; these paths always point into the System32 directory.
/// </summary>
public static class WindowsSystemExecutables
{
    /// <summary>Windows PowerShell 5.1, which lives below System32 rather than in its root.</summary>
    public static string PowerShell =>
        Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

    /// <summary>A tool that ships in the root of the System32 directory, such as <c>ipconfig.exe</c>.</summary>
    public static string System32(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        if (Path.GetFileName(fileName) != fileName)
        {
            throw new ArgumentException("Expected a bare file name.", nameof(fileName));
        }

        return Path.Combine(Environment.SystemDirectory, fileName);
    }
}
