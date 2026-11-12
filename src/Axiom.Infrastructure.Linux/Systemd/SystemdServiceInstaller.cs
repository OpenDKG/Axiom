// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Linux.Dns;
using Axiom.Infrastructure.Unix;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Install;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Systemd;

/// <summary>Paths the installer touches; tests point every one at a temp folder.</summary>
public sealed record SystemdInstallerOptions(
    string UnitPath,
    string ImageDirectory,
    string MachineDataDirectory,
    string RunDirectory,
    string DnsBackupPath,
    string ProtectionSettingsPath)
{
    public static SystemdInstallerOptions Default { get; } = new(
        LinuxServicePaths.UnitFilePath,
        LinuxServicePaths.ImageDirectory,
        LinuxServicePaths.Default.MachineDataDirectory,
        LinuxServicePaths.Default.RunDirectory,
        LinuxServicePaths.Default.DnsBackupFile,
        ProtectionSettingsStore.DefaultPath);

    /// <summary>systemd's <c>LogsDirectory=</c> (<c>/var/log/axiom</c>); 0700 with 0600 files when present.</summary>
    public string LogDirectory { get; init; } = LinuxServicePaths.LogDirectory;

    public string ImageRoot => Path.GetDirectoryName(ImageDirectory) ?? "/";

    public string DaemonPath => Path.Combine(ImageDirectory, ProtectedImageLayout.DaemonFileName);
}

/// <summary>
/// Registers axiomd as the system service <c>axiomd.service</c> and removes it again; the Linux
/// twin of <c>LaunchdServiceInstaller</c> with the same steps and messages: copy the publish tree
/// to the root-owned image directory (<c>/usr/libexec/axiom</c>), verify owner and modes, stop a
/// running instance and wait for it, swap the image in, check the daemon hash against the
/// installer image, record the installing user as IPC owner, write the unit (0644),
/// <c>daemon-reload</c>, <c>enable --now</c>. <c>--dry-run</c> prints the plan and the unit text
/// without touching the system and needs no root.
/// </summary>
public sealed class SystemdServiceInstaller
{
    public const string Systemctl = "/usr/bin/systemctl";

    public const string Chown = "/usr/bin/chown";

    public const string DryRunFlag = "--dry-run";

    private const int StartAttempts = 8;

    private static readonly TimeSpan StartRetryDelay = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(30);

    private readonly IProcessRunner _runner;

    private readonly SystemdInstallerOptions _options;

    private readonly Func<bool> _isPrivileged;

    private readonly Func<uint?> _detectOwner;

    private readonly Func<TimeSpan, bool> _sleep;

    public SystemdServiceInstaller()
        : this(ProcessRunner.Instance, SystemdInstallerOptions.Default, () => Environment.IsPrivilegedProcess, null, null)
    {
    }

    public SystemdServiceInstaller(
        IProcessRunner runner,
        SystemdInstallerOptions options,
        Func<bool> isPrivileged,
        Func<uint?>? detectOwner,
        Func<TimeSpan, bool>? sleep)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _isPrivileged = isPrivileged ?? throw new ArgumentNullException(nameof(isPrivileged));
        _detectOwner = detectOwner ?? InstallOwner.DetectLinux;
        _sleep = sleep ?? (delay =>
        {
            Thread.Sleep(delay);
            return true;
        });
    }

    public static string ServiceTarget => LinuxServicePaths.UnitName;

    public static bool IsDryRun(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Any(argument => string.Equals(argument, DryRunFlag, StringComparison.OrdinalIgnoreCase));
    }

    /// <param name="executablePath">The running axiomd; its directory is the publish tree to copy.</param>
    public int Install(string executablePath, TextWriter output, TextWriter error) => Install(executablePath, output, error, dryRun: false);

    public int Install(string executablePath, TextWriter output, TextWriter error, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            error.WriteLine($"axiomd executable not found: {executablePath}");
            return 2;
        }

        var sourceDirectory = Path.GetDirectoryName(Path.GetFullPath(executablePath)) ?? "/";
        var runningFromImage = string.Equals(sourceDirectory, _options.ImageDirectory, StringComparison.Ordinal);
        var unit = SystemdUnit.Build(_options.DaemonPath, _options.MachineDataDirectory, _options.RunDirectory);

        if (dryRun)
        {
            WritePlan(executablePath, sourceDirectory, runningFromImage, unit, output);
            return 0;
        }

        if (!_isPrivileged())
        {
            error.WriteLine("Installing the axiomd systemd service requires root (run with sudo or pkexec).");
            return 5;
        }

        var ownerUid = _detectOwner();
        string? staged = null;
        try
        {
            if (!runningFromImage)
            {
                staged = Stage(sourceDirectory);
                var stagedProblems = Verify(staged);
                if (stagedProblems.Count > 0)
                {
                    Report(error, "Refusing to install: the copied daemon is not root-owned and read-only.", stagedProblems);
                    return 3;
                }
            }

            // Stop the running instance (upgrade); "not loaded" is expected on first install. Like
            // the Windows and macOS installers, a pending stop is awaited before the image is replaced.
            _runner.Run(Systemctl, ["stop", ServiceTarget], ToolTimeout);
            if (!WaitForStop())
            {
                error.WriteLine("The existing Axiom service did not stop in time.");
            }

            if (staged is not null)
            {
                Replace(staged);
                staged = null;
            }

            var problems = Verify(_options.ImageDirectory);
            if (problems.Count > 0)
            {
                Report(error, $"Refusing to start: {_options.ImageDirectory} is not root-owned and read-only.", problems);
                return 3;
            }

            if (!runningFromImage && !ProtectedImageLayout.FilesMatch(executablePath, _options.DaemonPath))
            {
                error.WriteLine("The protected service copy does not match the installer image.");
                return 7;
            }

            Directory.CreateDirectory(_options.MachineDataDirectory);
            UnixDataDirectoryPermissions.Enforce(_options.MachineDataDirectory);
            // An older unit created /var/log/axiom 0750; tighten it (and any file log) on upgrade
            // before the new unit's LogsDirectoryMode=0700 takes over.
            foreach (var fixedPath in UnixLogPermissions.EnforceDirectory(_options.LogDirectory))
            {
                output.WriteLine($"Tightened log permissions on {fixedPath}.");
            }

            RecordOwner(ownerUid, output);
            Directory.CreateDirectory(Path.GetDirectoryName(_options.UnitPath) ?? "/");
            FilterRulesFile.WriteAtomic(_options.UnitPath, unit, ProtectedImageLayout.FileMode);
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

        var reload = _runner.Run(Systemctl, ["daemon-reload"], ToolTimeout);
        if (!reload.Succeeded)
        {
            error.WriteLine($"systemctl daemon-reload failed ({reload.ExitCode}): {reload.StandardError.Trim()}");
            return 1;
        }

        var start = _runner.Run(Systemctl, ["enable", "--now", ServiceTarget], ToolTimeout);
        for (var attempt = 1; attempt < StartAttempts && !start.Succeeded; attempt++)
        {
            // The old instance may still be shutting down (its shutdown restores DNS first); a
            // failed start with the shield on would strand DNS at 127.0.0.1, so keep trying.
            _sleep(StartRetryDelay);
            start = _runner.Run(Systemctl, ["enable", "--now", ServiceTarget], ToolTimeout);
        }

        if (!start.Succeeded)
        {
            error.WriteLine($"systemctl enable --now failed ({start.ExitCode}): {start.StandardError.Trim()}");
            return 1;
        }

        output.WriteLine($"Installed and started {ServiceTarget} from {_options.ImageDirectory} ({_options.UnitPath}).");
        return 0;
    }

    public int Uninstall(TextWriter output, TextWriter error) => Uninstall(output, error, dryRun: false);

    public int Uninstall(TextWriter output, TextWriter error, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (dryRun)
        {
            output.WriteLine($"[dry-run] systemctl disable --now {ServiceTarget}");
            output.WriteLine($"[dry-run] remove {_options.UnitPath}; systemctl daemon-reload");
            output.WriteLine($"[dry-run] nft delete table inet {Nft.NftRuleCompiler.TableName}; return herded processes and remove /sys/fs/cgroup/{Nft.AppCgroupManager.DefaultSlice} when present");
            output.WriteLine($"[dry-run] restore Privacy Shield DNS from {_options.DnsBackupPath} when present");
            output.WriteLine($"[dry-run] remove {_options.ImageDirectory}");
            output.WriteLine($"[dry-run] keep {_options.MachineDataDirectory} (rules, settings, database)");
            return 0;
        }

        if (!_isPrivileged())
        {
            error.WriteLine("Removing the axiomd systemd service requires root (run with sudo or pkexec).");
            return 5;
        }

        // disable --now waits for the daemon to exit; its shutdown restores Privacy Shield DNS.
        var stop = _runner.Run(Systemctl, ["disable", "--now", ServiceTarget], ToolTimeout);
        var code = 0;
        try
        {
            if (File.Exists(_options.UnitPath))
            {
                File.Delete(_options.UnitPath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not remove {_options.UnitPath}: {exception.Message}");
            code = 1;
        }

        _runner.Run(Systemctl, ["daemon-reload"], ToolTimeout);

        // The daemon's own stop tears the nftables table and cgroups down; repeat it here for a
        // daemon that crashed or was killed, so no Axiom rule ever outlives the install.
        RemoveEnforcementLeftovers(output);

        // The daemon may have been stopped, crashed or never started: restore DNS from the backup
        // here so an uninstall never leaves the system pointing at a resolver that is gone.
        if (File.Exists(_options.DnsBackupPath))
        {
            RestoreDns(_runner, _options.DnsBackupPath, output);
        }

        try
        {
            if (Directory.Exists(_options.ImageDirectory))
            {
                Directory.Delete(_options.ImageDirectory, recursive: true);
                output.WriteLine($"Removed {_options.ImageDirectory}.");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Could not remove {_options.ImageDirectory}: {exception.Message}");
            code = 1;
        }

        output.WriteLine(stop.Succeeded
            ? $"Stopped and removed {ServiceTarget}."
            : $"Removed {_options.UnitPath} ({ServiceTarget} was not running).");
        return code;
    }

    private void WritePlan(string executablePath, string sourceDirectory, bool runningFromImage, string unit, TextWriter output)
    {
        output.WriteLine($"[dry-run] axiomd --install-service plan (nothing is changed; root {(_isPrivileged() ? "available" : "not available")})");
        output.WriteLine(runningFromImage
            ? $"[dry-run] {executablePath} already runs from {_options.ImageDirectory}; no copy."
            : $"[dry-run] copy {sourceDirectory} -> {_options.ImageDirectory} (chown -R 0:0, dirs 0755, files 0644, executables 0755), verify with stat");
        output.WriteLine($"[dry-run] systemctl stop {ServiceTarget}; wait until inactive; swap image; verify SHA-256 of {_options.DaemonPath}");
        output.WriteLine($"[dry-run] enforce 0700/0600 under {_options.MachineDataDirectory}; record IPC owner uid in {_options.ProtectionSettingsPath}");
        output.WriteLine($"[dry-run] write {_options.UnitPath} (0644); systemctl daemon-reload; systemctl enable --now {ServiceTarget}");
        output.WriteLine("[dry-run] unit file:");
        output.Write(unit);
    }

    private void RemoveEnforcementLeftovers(TextWriter output)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var deleted = _runner.Run(Nft.NftProcessRunner.DefaultBinary, ["delete", "table", "inet", Nft.NftRuleCompiler.TableName], ToolTimeout);
        if (deleted.Succeeded)
        {
            output.WriteLine($"Removed leftover table inet {Nft.NftRuleCompiler.TableName}.");
        }

        if (!Directory.Exists(Path.Combine(Nft.ProcCgroupFs.DefaultCgroupRoot, Nft.AppCgroupManager.DefaultSlice)))
        {
            return;
        }

        try
        {
            var removed = new Nft.AppCgroupManager(new Nft.ProcCgroupFs()).RemoveAll();
            output.WriteLine($"Removed leftover cgroups: {string.Join(", ", removed)}.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"Could not remove /sys/fs/cgroup/{Nft.AppCgroupManager.DefaultSlice}: {exception.Message}");
        }
    }

    private static bool RestoreDns(IProcessRunner runner, string backupPath, TextWriter output)
    {
        var backend = LinuxDnsBackendDetector.Create(LinuxDnsBackendDetector.Detect(runner), runner);
        var restored = new LinuxDnsConfigurator(backend, backupPath).RestoreIfNeeded();
        output.WriteLine(restored
            ? "Restored system DNS from the Privacy Shield backup."
            : "Privacy Shield DNS backup checked; system DNS was already restored.");
        return restored;
    }

    /// <summary>Copies the publish tree next to the image directory with final modes and root ownership.</summary>
    private string Stage(string sourceDirectory)
    {
        Directory.CreateDirectory(_options.ImageRoot);
        var staged = Path.Combine(_options.ImageRoot, $".{Path.GetFileName(_options.ImageDirectory)}.{Guid.NewGuid():N}.tmp");
        Directory.CreateDirectory(staged);
        SetMode(staged, ProtectedImageLayout.DirectoryMode);

        foreach (var entry in Directory.EnumerateFileSystemEntries(sourceDirectory, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceDirectory, entry);
            var target = Path.Combine(staged, relative);
            if (Directory.Exists(entry))
            {
                Directory.CreateDirectory(target);
                SetMode(target, ProtectedImageLayout.DirectoryMode);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(entry, target, overwrite: false);
            var sourceMode = OperatingSystem.IsWindows() ? UnixFileMode.None : File.GetUnixFileMode(entry);
            SetMode(target, ProtectedImageLayout.ModeFor(isDirectory: false, sourceMode));
        }

        var chown = _runner.Run(Chown, ["-R", "0:0", staged], ToolTimeout);
        if (!chown.Succeeded)
        {
            throw new IOException($"chown -R 0:0 {staged} failed ({chown.ExitCode}): {chown.StandardError.Trim()}");
        }

        return staged;
    }

    private void Replace(string staged)
    {
        string? previous = null;
        if (Directory.Exists(_options.ImageDirectory))
        {
            previous = _options.ImageDirectory + ".old-" + Guid.NewGuid().ToString("N");
            Directory.Move(_options.ImageDirectory, previous);
        }

        Directory.Move(staged, _options.ImageDirectory);
        TryDeleteDirectory(previous);
    }

    private List<string> Verify(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return [$"{directory} does not exist."];
        }

        var paths = ProtectedImageLayout.EnumerateTree(directory);
        var entries = UnixFileStat.List(_runner, paths, StatFlavor.Gnu);
        var problems = new List<string>();
        if (entries.Count != paths.Count)
        {
            problems.Add($"stat listed {entries.Count} of {paths.Count} entries under {directory}.");
        }

        problems.AddRange(ProtectedImageLayout.Audit(directory, entries));
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
            ? $"IPC write commands are allowed for uid {uid.ToString(CultureInfo.InvariantCulture)} (installing user), root and members of the axiom, sudo or wheel groups."
            : "No installing user was detected; IPC write commands are allowed for root and members of the axiom, sudo or wheel groups only.");
    }

    /// <summary>After <c>systemctl stop</c>, poll <c>is-active</c> until the unit is no longer active (at most ~15 s).</summary>
    private bool WaitForStop()
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            var state = _runner.Run(Systemctl, ["is-active", ServiceTarget], ToolTimeout);
            var text = state.StandardOutput.Trim();
            if (!string.Equals(text, "active", StringComparison.Ordinal) && !string.Equals(text, "deactivating", StringComparison.Ordinal))
            {
                return true;
            }

            if (!_sleep(TimeSpan.FromMilliseconds(500)))
            {
                return false;
            }
        }

        return false;
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
