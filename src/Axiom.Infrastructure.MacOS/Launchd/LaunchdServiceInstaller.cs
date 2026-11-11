// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Security;
using System.Text;
using Axiom.Core.Protection;
using Axiom.Infrastructure.MacOS.Dns;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Launchd;

/// <summary>Paths the installer touches; tests point every one at a temp folder.</summary>
public sealed record LaunchdInstallerOptions(
    string PlistPath,
    string LogDirectory,
    string HelperDirectory,
    string MachineDataDirectory,
    string DnsBackupPath,
    string ProtectionSettingsPath)
{
    public static LaunchdInstallerOptions Default { get; } = new(
        MacServicePaths.LaunchDaemonPlistPath,
        MacServicePaths.LogDirectory,
        PrivilegedHelperLayout.HelperDirectory,
        MacServicePaths.Default.MachineDataDirectory,
        MacServicePaths.Default.DnsBackupFile,
        ProtectionSettingsStore.DefaultPath);

    public string HelperRoot => Path.GetDirectoryName(HelperDirectory) ?? "/";

    public string DaemonPath => Path.Combine(HelperDirectory, PrivilegedHelperLayout.DaemonFileName);
}

/// <summary>
/// Registers axiomd as the system launchd daemon <c>com.axiom.service</c>
/// (<c>/Library/LaunchDaemons/com.axiom.service.plist</c>, root:wheel 0644) and removes it again.
/// This is the macOS counterpart of the Windows <c>--install-service</c> / <c>--uninstall-service</c>
/// helper and the only step that needs administrator rights.
/// <para>
/// Install copies the running daemon's publish directory to the root-owned helper location
/// (<see cref="PrivilegedHelperLayout"/>), verifies owner and modes, records the installing user
/// as the IPC owner uid, writes the plist pointing at the copy and bootstraps it. Re-running
/// upgrades in place (stop, replace, start). Uninstall stops the job, removes plist and helper,
/// and restores Privacy Shield DNS from the backup even when the daemon is not running.
/// </para>
/// </summary>
public sealed class LaunchdServiceInstaller
{
    public const string ServiceEnvironmentVariable = "AXIOM_SERVICE";

    private const string Launchctl = "/bin/launchctl";

    private const string Chown = "/usr/sbin/chown";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(30);

    private readonly IProcessRunner _runner;

    private readonly LaunchdInstallerOptions _options;

    private readonly Func<bool> _isPrivileged;

    private readonly Func<uint?> _detectOwner;

    public LaunchdServiceInstaller()
        : this(ProcessRunner.Instance, LaunchdInstallerOptions.Default, () => Environment.IsPrivilegedProcess, null)
    {
    }

    public LaunchdServiceInstaller(
        IProcessRunner runner,
        LaunchdInstallerOptions options,
        Func<bool> isPrivileged,
        Func<uint?>? detectOwner)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _isPrivileged = isPrivileged ?? throw new ArgumentNullException(nameof(isPrivileged));
        _detectOwner = detectOwner ?? (() => InstallOwner.Detect(_runner));
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

    /// <param name="executablePath">The running axiomd; its directory is the publish tree to copy.</param>
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

        var sourceDirectory = Path.GetDirectoryName(Path.GetFullPath(executablePath)) ?? "/";
        var runningFromHelper = string.Equals(sourceDirectory, _options.HelperDirectory, StringComparison.Ordinal);
        var ownerUid = _detectOwner();

        string? staged = null;
        try
        {
            if (!runningFromHelper)
            {
                staged = Stage(sourceDirectory);
                var stagedProblems = Verify(staged);
                if (stagedProblems.Count > 0)
                {
                    Report(error, "Refusing to install: the copied daemon is not root-owned and read-only.", stagedProblems);
                    return 3;
                }
            }

            Directory.CreateDirectory(_options.LogDirectory);
            var plist = BuildPlist(_options.DaemonPath, Path.Combine(_options.LogDirectory, Path.GetFileName(MacServicePaths.LogFilePath)));

            // Stop the running instance (upgrade); "not loaded" is expected on first install.
            _runner.Run(Launchctl, ["bootout", ServiceTarget], ToolTimeout);

            if (staged is not null)
            {
                Replace(staged);
                staged = null;
            }

            var problems = Verify(_options.HelperDirectory);
            if (problems.Count > 0)
            {
                Report(error, $"Refusing to bootstrap: {_options.HelperDirectory} is not root-owned and read-only.", problems);
                return 3;
            }

            MacDataDirectoryPermissions.Enforce(_options.MachineDataDirectory);
            RecordOwner(ownerUid, output);
            FilterRulesFile.WriteAtomic(_options.PlistPath, plist, PrivilegedHelperLayout.FileMode);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not install the daemon: {exception.Message}");
            return 1;
        }
        finally
        {
            TryDeleteDirectory(staged);
        }

        _runner.Run(Launchctl, ["enable", ServiceTarget], ToolTimeout);
        var bootstrap = _runner.Run(Launchctl, ["bootstrap", "system", _options.PlistPath], ToolTimeout);
        if (!bootstrap.Succeeded)
        {
            // launchd may still be tearing the old job down; retry once.
            Thread.Sleep(TimeSpan.FromSeconds(1));
            bootstrap = _runner.Run(Launchctl, ["bootstrap", "system", _options.PlistPath], ToolTimeout);
        }

        if (!bootstrap.Succeeded)
        {
            error.WriteLine($"launchctl bootstrap failed ({bootstrap.ExitCode}): {bootstrap.StandardError.Trim()}");
            return 1;
        }

        output.WriteLine($"Installed and started {ServiceTarget} from {_options.HelperDirectory} ({_options.PlistPath}).");
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
        var code = 0;
        try
        {
            if (File.Exists(_options.PlistPath))
            {
                File.Delete(_options.PlistPath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not remove {_options.PlistPath}: {exception.Message}");
            code = 1;
        }

        // The daemon may have been stopped, crashed or never started: restore DNS from the backup
        // here so an uninstall never leaves the system pointing at a resolver that is gone.
        if (File.Exists(_options.DnsBackupPath))
        {
            var restored = new MacDnsConfigurator(_runner, _options.DnsBackupPath).RestoreIfNeeded();
            output.WriteLine(restored
                ? "Restored system DNS from the Privacy Shield backup."
                : "Privacy Shield DNS backup checked; system DNS was already restored.");
        }

        try
        {
            if (Directory.Exists(_options.HelperDirectory))
            {
                Directory.Delete(_options.HelperDirectory, recursive: true);
                output.WriteLine($"Removed {_options.HelperDirectory}.");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not remove {_options.HelperDirectory}: {exception.Message}");
            code = 1;
        }

        output.WriteLine(bootout.Succeeded
            ? $"Stopped and removed {ServiceTarget}."
            : $"Removed {_options.PlistPath} ({ServiceTarget} was not running).");
        return code;
    }

    /// <summary>Copies the publish tree next to the helper directory with final modes and root ownership.</summary>
    private string Stage(string sourceDirectory)
    {
        Directory.CreateDirectory(_options.HelperRoot);
        SetMode(_options.HelperRoot, PrivilegedHelperLayout.DirectoryMode);

        var staged = Path.Combine(_options.HelperRoot, $".{Path.GetFileName(_options.HelperDirectory)}.{Guid.NewGuid():N}.tmp");
        Directory.CreateDirectory(staged);
        SetMode(staged, PrivilegedHelperLayout.DirectoryMode);

        foreach (var entry in Directory.EnumerateFileSystemEntries(sourceDirectory, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceDirectory, entry);
            var target = Path.Combine(staged, relative);
            if (Directory.Exists(entry))
            {
                Directory.CreateDirectory(target);
                SetMode(target, PrivilegedHelperLayout.DirectoryMode);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(entry, target, overwrite: false);
            var sourceMode = OperatingSystem.IsWindows() ? UnixFileMode.None : File.GetUnixFileMode(entry);
            SetMode(target, PrivilegedHelperLayout.ModeFor(isDirectory: false, sourceMode));
        }

        var chown = _runner.Run(Chown, ["-R", "0:0", staged], ToolTimeout);
        if (!chown.Succeeded)
        {
            throw new IOException($"chown -R 0:0 {staged} failed ({chown.ExitCode}): {chown.StandardError.Trim()}");
        }

        return staged;
    }

    /// <summary>Atomically swaps the staged copy into place and removes the previous one.</summary>
    private void Replace(string staged)
    {
        string? previous = null;
        if (Directory.Exists(_options.HelperDirectory))
        {
            previous = _options.HelperDirectory + ".old-" + Guid.NewGuid().ToString("N");
            Directory.Move(_options.HelperDirectory, previous);
        }

        Directory.Move(staged, _options.HelperDirectory);
        TryDeleteDirectory(previous);
    }

    private List<string> Verify(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return [$"{directory} does not exist."];
        }

        var paths = PrivilegedHelperLayout.EnumerateTree(directory);
        var entries = UnixFileStat.List(_runner, paths);
        var problems = new List<string>();
        if (entries.Count != paths.Count)
        {
            problems.Add($"stat listed {entries.Count} of {paths.Count} entries under {directory}.");
        }

        problems.AddRange(PrivilegedHelperLayout.Audit(directory, entries));
        return problems;
    }

    private void RecordOwner(uint? ownerUid, TextWriter output)
    {
        var store = new ProtectionSettingsStore(_options.ProtectionSettingsPath);
        var settings = store.Load();
        if (settings.AllowedUid != ownerUid)
        {
            store.Save(settings with { AllowedUid = ownerUid });
        }

        output.WriteLine(ownerUid is { } uid
            ? $"IPC write commands are allowed for uid {uid.ToString(CultureInfo.InvariantCulture)} (installing user), root and members of the admin group."
            : "No installing user was detected; IPC write commands are allowed for root and members of the admin group only.");
    }

    private static void Report(TextWriter error, string headline, IReadOnlyList<string> problems)
    {
        error.WriteLine(headline);
        foreach (var problem in problems)
        {
            error.WriteLine("  " + problem);
        }
    }

    private static void SetMode(string path, UnixFileMode mode)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, mode);
        }
    }

    private static void TryDeleteDirectory(string? path)
    {
        if (path is null || !Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Leftover staging/previous directory; harmless, removed by the next install.
        }
    }
}
