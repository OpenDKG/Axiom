// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Security;
using System.Text;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Launchd;

/// <summary>
/// Registers axiomd as the system launchd daemon <c>com.axiom.service</c>
/// (<c>/Library/LaunchDaemons/com.axiom.service.plist</c>, root:wheel 0644) and removes it again.
/// This is the macOS counterpart of the Windows <c>--install-service</c> / <c>--uninstall-service</c>
/// helper and the only step that needs administrator rights.
/// </summary>
public sealed class LaunchdServiceInstaller
{
    public const string ServiceEnvironmentVariable = "AXIOM_SERVICE";

    private const string Launchctl = "/bin/launchctl";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(30);

    private readonly IProcessRunner _runner;

    private readonly string _plistPath;

    private readonly string _logDirectory;

    private readonly Func<bool> _isPrivileged;

    public LaunchdServiceInstaller()
        : this(
            ProcessRunner.Instance,
            MacServicePaths.LaunchDaemonPlistPath,
            MacServicePaths.LogDirectory,
            () => Environment.IsPrivilegedProcess)
    {
    }

    public LaunchdServiceInstaller(IProcessRunner runner, string plistPath, string logDirectory, Func<bool> isPrivileged)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        ArgumentException.ThrowIfNullOrWhiteSpace(plistPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(logDirectory);
        _plistPath = plistPath;
        _logDirectory = logDirectory;
        _isPrivileged = isPrivileged ?? throw new ArgumentNullException(nameof(isPrivileged));
    }

    public static string ServiceTarget => "system/" + MacServicePaths.LaunchdLabel;

    /// <summary>The launchd job definition (pure; unit-tested).</summary>
    public static string BuildPlist(string executablePath, string logFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(logFilePath);

        static string X(string value) => SecurityElement.Escape(value);

        var workingDirectory = Path.GetDirectoryName(executablePath) ?? "/";
        var builder = new StringBuilder();
        builder.Append("""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
            """).Append('\n');
        builder.Append(CultureInfo.InvariantCulture, $"""
                <key>Label</key>
                <string>{X(MacServicePaths.LaunchdLabel)}</string>
                <key>ProgramArguments</key>
                <array>
                    <string>{X(executablePath)}</string>
                </array>
                <key>WorkingDirectory</key>
                <string>{X(workingDirectory)}</string>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <true/>
                <key>ProcessType</key>
                <string>Interactive</string>
                <key>EnvironmentVariables</key>
                <dict>
                    <key>{ServiceEnvironmentVariable}</key>
                    <string>1</string>
                    <key>DOTNET_CLI_TELEMETRY_OPTOUT</key>
                    <string>1</string>
                </dict>
                <key>StandardOutPath</key>
                <string>{X(logFilePath)}</string>
                <key>StandardErrorPath</key>
                <string>{X(logFilePath)}</string>
            """).Append('\n');
        builder.Append("""
            </dict>
            </plist>
            """).Append('\n');
        return builder.ToString();
    }

    public int Install(string executablePath, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (!_isPrivileged())
        {
            error.WriteLine("Installing the axiomd launchd daemon requires root (run with sudo or an administrator prompt).");
            return 5;
        }

        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            error.WriteLine($"axiomd executable not found: {executablePath}");
            return 2;
        }

        try
        {
            Directory.CreateDirectory(_logDirectory);
            FilterRulesFile.WriteAtomic(
                _plistPath,
                BuildPlist(executablePath, Path.Combine(_logDirectory, Path.GetFileName(MacServicePaths.LogFilePath))));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not write {_plistPath}: {exception.Message}");
            return 1;
        }

        // Replace a running instance (upgrade); "not loaded" is expected on first install.
        _runner.Run(Launchctl, ["bootout", ServiceTarget], ToolTimeout);
        _runner.Run(Launchctl, ["enable", ServiceTarget], ToolTimeout);

        var bootstrap = _runner.Run(Launchctl, ["bootstrap", "system", _plistPath], ToolTimeout);
        if (!bootstrap.Succeeded)
        {
            // launchd may still be tearing the old job down; retry once.
            Thread.Sleep(TimeSpan.FromSeconds(1));
            bootstrap = _runner.Run(Launchctl, ["bootstrap", "system", _plistPath], ToolTimeout);
        }

        if (!bootstrap.Succeeded)
        {
            error.WriteLine($"launchctl bootstrap failed ({bootstrap.ExitCode}): {bootstrap.StandardError.Trim()}");
            return 1;
        }

        output.WriteLine($"Installed and started {ServiceTarget} ({_plistPath}).");
        return 0;
    }

    public int Uninstall(TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (!_isPrivileged())
        {
            error.WriteLine("Removing the axiomd launchd daemon requires root (run with sudo or an administrator prompt).");
            return 5;
        }

        // bootout waits for the daemon to exit; its shutdown restores Privacy Shield DNS.
        var bootout = _runner.Run(Launchctl, ["bootout", ServiceTarget], ToolTimeout);
        try
        {
            if (File.Exists(_plistPath))
            {
                File.Delete(_plistPath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not remove {_plistPath}: {exception.Message}");
            return 1;
        }

        output.WriteLine(bootout.Succeeded
            ? $"Stopped and removed {ServiceTarget}."
            : $"Removed {_plistPath} ({ServiceTarget} was not running).");
        return 0;
    }
}
