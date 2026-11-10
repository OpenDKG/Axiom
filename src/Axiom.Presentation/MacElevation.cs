// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace Axiom.Presentation;

/// <summary>Result of one administrator-approved shell command on macOS.</summary>
public sealed record MacElevationResult(int ExitCode, string StandardOutput, string StandardError)
{
    /// <summary>osascript reports "User canceled. (-128)" when the password dialog is dismissed.</summary>
    public bool Cancelled => StandardError.Contains("(-128)", StringComparison.Ordinal);

    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// The macOS counterpart of a UAC prompt: runs one shell command through
/// <c>osascript -e 'do shell script "…" with administrator privileges'</c>, which shows the standard
/// administrator password dialog. The desktop app itself never runs as root. All values are quoted
/// for both the shell and AppleScript so a path with spaces or quotes cannot change the command.
/// </summary>
public static class MacElevation
{
    public const string OsascriptPath = "/usr/bin/osascript";

    /// <summary>POSIX single-quote quoting: <c>it's</c> becomes <c>'it'\''s'</c>.</summary>
    public static string ShellQuote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    }

    /// <summary>AppleScript string literal with backslashes and double quotes escaped.</summary>
    public static string AppleScriptString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (var character in value)
        {
            switch (character)
            {
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\r':
                case '\n':
                    // A command is one line; a newline would start a second AppleScript statement.
                    builder.Append(' ');
                    break;
                default:
                    builder.Append(character);
                    break;
            }
        }

        builder.Append('"');
        return builder.ToString();
    }

    /// <summary>Builds the shell command line from an executable and its arguments.</summary>
    public static string BuildShellCommand(string executable, params string[] arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        ArgumentNullException.ThrowIfNull(arguments);
        return string.Join(' ', new[] { executable }.Concat(arguments).Select(ShellQuote));
    }

    /// <summary>The single AppleScript statement passed to <c>osascript -e</c>.</summary>
    public static string BuildAppleScript(string shellCommand, string? prompt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(shellCommand);
        var script = "do shell script " + AppleScriptString(shellCommand);
        if (!string.IsNullOrWhiteSpace(prompt))
        {
            script += " with prompt " + AppleScriptString(prompt);
        }

        return script + " with administrator privileges";
    }

    /// <summary>
    /// Shows the administrator dialog and runs <paramref name="shellCommand"/> as root. Returns
    /// exit code -1 off macOS or when osascript cannot start.
    /// </summary>
    public static async Task<MacElevationResult> RunAsync(
        string shellCommand,
        string? prompt,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return new MacElevationResult(-1, string.Empty, "Administrator prompts are only available on macOS.");
        }

        var startInfo = new ProcessStartInfo(OsascriptPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("-e");
        startInfo.ArgumentList.Add(BuildAppleScript(shellCommand, prompt));

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new MacElevationResult(-1, string.Empty, "osascript did not start.");
            }

            var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var error = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return new MacElevationResult(
                process.ExitCode,
                await output.ConfigureAwait(false),
                await error.ConfigureAwait(false));
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            return new MacElevationResult(-1, string.Empty, exception.Message);
        }
    }
}

/// <summary>
/// Paths inside <c>Axiom.app</c> (docs/MACOS_ARCHITECTURE.md §1), derived from the directory of the
/// running executable (<c>Contents/MacOS</c>). Pure so it can be tested on any OS.
/// </summary>
public sealed class MacBundleLayout
{
    public const string DaemonLabel = "com.axiom.service";

    public const string LaunchDaemonPlistPath = "/Library/LaunchDaemons/com.axiom.service.plist";

    public MacBundleLayout(string executableDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executableDirectory);
        MacOSDirectory = Path.TrimEndingDirectorySeparator(executableDirectory);
        var contents = Path.GetDirectoryName(MacOSDirectory);
        var bundle = contents is null ? null : Path.GetDirectoryName(contents);
        IsInsideAppBundle =
            string.Equals(Path.GetFileName(MacOSDirectory), "MacOS", StringComparison.Ordinal) &&
            contents is not null &&
            string.Equals(Path.GetFileName(contents), "Contents", StringComparison.Ordinal) &&
            bundle is not null &&
            bundle.EndsWith(".app", StringComparison.OrdinalIgnoreCase);
        ContentsDirectory = contents ?? MacOSDirectory;
        BundlePath = IsInsideAppBundle ? bundle : null;
    }

    public static MacBundleLayout Current { get; } = new(AppContext.BaseDirectory);

    public bool IsInsideAppBundle { get; }

    /// <summary><c>/Applications/Axiom.app</c>, or null when not running from a bundle.</summary>
    public string? BundlePath { get; }

    public string MacOSDirectory { get; }

    public string ContentsDirectory { get; }

    /// <summary>The bundled daemon, <c>Contents/Resources/service/axiomd</c>.</summary>
    public string DaemonPath => IsInsideAppBundle
        ? Path.Combine(ContentsDirectory, "Resources", "service", "axiomd")
        : Path.Combine(MacOSDirectory, "service", "axiomd");

    /// <summary>The system extension helper, <c>Contents/MacOS/axiom-sysext</c>.</summary>
    public string SysextHelperPath => Path.Combine(MacOSDirectory, "axiom-sysext");

    public bool IsInApplicationsFolder =>
        BundlePath is not null &&
        string.Equals(Path.GetDirectoryName(BundlePath), "/Applications", StringComparison.Ordinal);
}
