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
    string ProtectionSettingsPath,
    string NewsyslogConfPath)
{
    public static LaunchdInstallerOptions Default { get; } = new(
        MacServicePaths.LaunchDaemonPlistPath,
        MacServicePaths.LogDirectory,
        PrivilegedHelperLayout.HelperDirectory,
        MacServicePaths.Default.MachineDataDirectory,
        MacServicePaths.Default.DnsBackupFile,
        ProtectionSettingsStore.DefaultPath,
        LaunchdServiceInstaller.NewsyslogConfPath);

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

    /// <summary>newsyslog(8) rotation entry for the daemon log, written by install, removed by uninstall.</summary>
    public const string NewsyslogConfPath = "/etc/newsyslog.d/com.axiom.service.conf";

    /// <summary>Seconds launchd waits before respawning the daemon after an unsuccessful exit.</summary>
    public const int ThrottleIntervalSeconds = 10;

    /// <summary>Rotate at this size (newsyslog counts KiB).</summary>
    public const int LogRotateSizeKiB = 5 * 1024;

    public const int LogRotateKeep = 5;

    /// <summary>
    /// axiomd's pid file, named in the newsyslog entry so newsyslog sends <see cref="LogRotateSignal"/>
    /// after a rotation and the daemon reopens its log (<see cref="DaemonLogFile"/>).
    /// </summary>
    public const string PidFilePath = "/var/run/axiomd.pid";

    /// <summary>SIGHUP: axiomd reopens <c>axiomd.log</c>.</summary>
    public const int LogRotateSignal = 1;

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
                <dict>
                    <key>SuccessfulExit</key>
                    <false/>
                </dict>
                <key>ThrottleInterval</key>
                <integer>{ThrottleIntervalSeconds}</integer>
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

    /// <summary>
    /// The <c>/etc/newsyslog.d</c> entry: rotate <paramref name="logFilePath"/> at
    /// <see cref="LogRotateSizeKiB"/> KiB, keep <see cref="LogRotateKeep"/> archives, bzip2 them
    /// (flag <c>J</c>), mode 600 so the new log and the archives stay root-only
    /// (<see cref="MacLogPermissions"/>), and send SIGHUP to the pid in <see cref="PidFilePath"/>.
    /// launchd keeps the <c>StandardOutPath</c> descriptor it opened at spawn, so without the
    /// signal the daemon would keep writing into the rotated archive; axiomd writes its log
    /// itself and reopens it on the signal (<see cref="DaemonLogFile"/>).
    /// </summary>
    public static string BuildNewsyslogConf(string logFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logFilePath);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"""
            # Axiom daemon log rotation (written by axiomd --install-service, removed by --uninstall-service).
            # logfilename{"\t"}[owner:group]{"\t"}mode{"\t"}count{"\t"}size{"\t"}when{"\t"}flags{"\t"}[/pid_file]{"\t"}[sig_num]
            {logFilePath}{"\t"}root:wheel{"\t"}{MacLogPermissions.NewsyslogMode}{"\t"}{LogRotateKeep}{"\t"}{LogRotateSizeKiB}{"\t"}*{"\t"}J{"\t"}{PidFilePath}{"\t"}{LogRotateSignal}

            """);
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
        string? previous = null;
        byte[]? previousPlist = null;
        var plistWritten = false;
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

            // Pre-create the log root-only before launchd opens StandardOutPath with the default
            // umask; an upgrade also fixes the modes of an existing log and its archives.
            var logFile = Path.Combine(_options.LogDirectory, Path.GetFileName(MacServicePaths.LogFilePath));
            foreach (var fixedPath in MacLogPermissions.Enforce(_options.LogDirectory, logFile))
            {
                output.WriteLine($"Restricted {fixedPath} to root.");
            }

            var plist = BuildPlist(_options.DaemonPath, logFile);

            // Stop the running instance (upgrade); "not loaded" is expected on first install. A stop
            // that does not complete leaves the old daemon running with its protected image open, so
            // replacing it would be a half-swapped install: refuse instead.
            _runner.Run(Launchctl, ["bootout", ServiceTarget], ToolTimeout);
            if (!WaitForJobRemoval())
            {
                error.WriteLine(
                    $"The existing Axiom service did not stop within {JobRemovalAttempts * JobRemovalDelay.TotalSeconds:0}s; " +
                    "refusing to replace the installed daemon. Stop it with 'sudo launchctl bootout system/com.axiom.service' and retry.");
                return 6;
            }

            // Capture the job definition before touching either the helper or the plist: a failure
            // in the swap or in the write must be able to put the old job back.
            previousPlist = File.Exists(_options.PlistPath) ? File.ReadAllBytes(_options.PlistPath) : null;
            if (staged is not null)
            {
                Swap(staged, _options.HelperDirectory, out previous);
                staged = null;
            }

            var problems = Verify(_options.HelperDirectory);
            if (problems.Count > 0)
            {
                Report(error, $"Refusing to bootstrap: {_options.HelperDirectory} is not root-owned and read-only.", problems);
                return RollBackInstall(3, previous, previousPlist, plistWritten, error);
            }

            if (!runningFromHelper && !FilesMatch(executablePath, _options.DaemonPath))
            {
                error.WriteLine("The protected service copy does not match the installer image.");
                return RollBackInstall(7, previous, previousPlist, plistWritten, error);
            }

            MacDataDirectoryPermissions.Enforce(_options.MachineDataDirectory);
            RecordOwner(ownerUid, output);
            FilterRulesFile.WriteAtomic(_options.PlistPath, plist, PrivilegedHelperLayout.FileMode);
            plistWritten = true;
            WriteNewsyslogConf(logFile, output);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not install the daemon: {exception.Message}");
            return RollBackInstall(1, previous, previousPlist, plistWritten, error);
        }
        finally
        {
            TryDeleteDirectory(staged);
        }

        _runner.Run(Launchctl, ["enable", ServiceTarget], ToolTimeout);
        var bootstrap = _runner.Run(Launchctl, ["bootstrap", "system", _options.PlistPath], ToolTimeout);
        for (var attempt = 1; attempt < BootstrapAttempts && !bootstrap.Succeeded; attempt++)
        {
            // "Bootstrap failed: 5: Input/output error" while launchd is still tearing the old job
            // down (its shutdown restores DNS first). A failed bootstrap with the shield on would
            // strand DNS at 127.0.0.1, so keep trying for a while.
            Thread.Sleep(BootstrapRetryDelay);
            bootstrap = _runner.Run(Launchctl, ["bootstrap", "system", _options.PlistPath], ToolTimeout);
        }

        if (!bootstrap.Succeeded)
        {
            error.WriteLine($"launchctl bootstrap failed ({bootstrap.ExitCode}): {bootstrap.StandardError.Trim()}");
            RollBackInstall(1, previous, previousPlist, plistWritten, error);
            return 1;
        }

        TryDeleteDirectory(previous);
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
            RestoreDns(_runner, _options.DnsBackupPath, output);
        }

        try
        {
            if (File.Exists(_options.NewsyslogConfPath))
            {
                File.Delete(_options.NewsyslogConfPath);
                output.WriteLine($"Removed {_options.NewsyslogConfPath}.");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not remove {_options.NewsyslogConfPath}: {exception.Message}");
            code = 1;
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

    /// <summary>
    /// <c>axiomd --restore-dns</c>: puts the saved DNS servers back without the daemon. For the
    /// case the bundle or helper is gone while Privacy Shield still pointed the system at
    /// 127.0.0.1 (launchd cannot start a missing program, so the daemon's own fail-safe never runs).
    /// </summary>
    // Offline DNS/rule recovery without the daemon is upstream's `axiomd --recover-network [--apply]`
    // (NetworkRecoveryCommand over the network-recovery.txt baseline); the Privacy Shield backup is
    // only used here to undo a redirect when the daemon is removed.
    private static bool RestoreDns(IProcessRunner runner, string backupPath, TextWriter output)
    {
        var restored = new MacDnsConfigurator(runner, backupPath).RestoreIfNeeded();
        output.WriteLine(restored
            ? "Restored system DNS from the Privacy Shield backup."
            : "Privacy Shield DNS backup checked; system DNS was already restored.");
        return restored;
    }

    private void WriteNewsyslogConf(string logFile, TextWriter output)
    {
        var directory = Path.GetDirectoryName(_options.NewsyslogConfPath);
        if (directory is null)
        {
            return;
        }

        Directory.CreateDirectory(directory);
        FilterRulesFile.WriteAtomic(_options.NewsyslogConfPath, BuildNewsyslogConf(logFile), PrivilegedHelperLayout.FileMode);
        output.WriteLine($"Log rotation: {_options.NewsyslogConfPath} ({LogRotateSizeKiB / 1024} MB, keep {LogRotateKeep}, compressed).");
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

    /// <summary>
    /// Swaps the staged copy into place. <paramref name="previous"/> is set as soon as the old copy
    /// has been moved aside, before the second move can throw, so the caller can restore it.
    /// </summary>
    internal static void Swap(string staged, string helperDirectory, out string? previous)
    {
        previous = null;
        if (Directory.Exists(helperDirectory))
        {
            previous = helperDirectory + ".old-" + Guid.NewGuid().ToString("N");
            Directory.Move(helperDirectory, previous);
        }

        Directory.Move(staged, helperDirectory);
    }

    /// <summary>
    /// Undoes a failed install after the helper swap: restores the plist this attempt overwrote
    /// (or removes one it created, so a half-install does not autostart at next boot) and then
    /// restores the previous daemon copy. If the plist could not be restored, the daemon copy is
    /// restored but not started, so it never runs with the wrong job definition. Returns
    /// <paramref name="code"/> so callers can <c>return RollBackInstall(...)</c>.
    /// </summary>
    internal int RollBackInstall(int code, string? previous, byte[]? previousPlist, bool plistWritten, TextWriter error)
    {
        var canStart = true;
        if (plistWritten)
        {
            try
            {
                if (previousPlist is null)
                {
                    File.Delete(_options.PlistPath);
                    error.WriteLine($"Removed {_options.PlistPath}, written by the failed install.");
                }
                else
                {
                    File.WriteAllBytes(_options.PlistPath, previousPlist);
                    SetMode(_options.PlistPath, PrivilegedHelperLayout.FileMode);
                    error.WriteLine($"Restored the previous {_options.PlistPath}.");
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                canStart = false;
                error.WriteLine($"Could not restore {_options.PlistPath}: {exception.Message}");
            }
        }

        if (previous is not null)
        {
            RollBack(previous, canStart, error);
        }

        return code;
    }

    /// <summary>
    /// Puts the previous daemon copy back. It is started only when the previous plist was restored
    /// successfully; the plist and helper paths do not change across an upgrade.
    /// </summary>
    private void RollBack(string previous, bool canStart, TextWriter error)
    {
        try
        {
            TryDeleteDirectory(_options.HelperDirectory);
            Directory.Move(previous, _options.HelperDirectory);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not restore the previous daemon copy from {previous}: {exception.Message}");
            return;
        }

        if (!canStart)
        {
            error.WriteLine("Restored the previous daemon copy but will not start it: the previous plist could not be restored.");
            return;
        }

        var bootstrap = _runner.Run(Launchctl, ["bootstrap", "system", _options.PlistPath], ToolTimeout);
        error.WriteLine(bootstrap.Succeeded
            ? "Restored and started the previous daemon copy after the failed upgrade."
            : $"The previous daemon copy was restored but launchctl bootstrap still failed ({bootstrap.ExitCode}): {bootstrap.StandardError.Trim()}");
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

    private const int BootstrapAttempts = 8;

    /// <summary>Delay between bootstrap attempts; tests shorten it.</summary>
    internal TimeSpan BootstrapRetryDelay { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Poll budget for <see cref="WaitForJobRemoval"/>; tests shorten it.</summary>
    internal int JobRemovalAttempts { get; init; } = 30;

    internal TimeSpan JobRemovalDelay { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// After <c>bootout</c> returns, launchd may still hold the job while the old daemon exits
    /// (DNS restore, socket cleanup). Poll <c>launchctl print</c> until it no longer finds the job,
    /// ~15 s by default, so the caller can refuse the upgrade rather than replace a running image.
    /// </summary>
    private bool WaitForJobRemoval()
    {
        for (var attempt = 0; attempt < JobRemovalAttempts; attempt++)
        {
            var print = _runner.Run(Launchctl, ["print", ServiceTarget], ToolTimeout);
            if (!print.Succeeded)
            {
                return true;
            }

            Thread.Sleep(JobRemovalDelay);
        }

        return false;
    }

    /// <summary>
    /// Same check as the Windows installer after the copy to Program Files: the installed daemon
    /// must be byte-identical to the image the administrator prompt ran.
    /// </summary>
    internal static bool FilesMatch(string left, string right)
    {
        try
        {
            return string.Equals(Hash(left), Hash(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
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
