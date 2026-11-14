// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.MacOS;
using Axiom.Infrastructure.MacOS.Diagnostics;
using Axiom.Infrastructure.MacOS.Dns;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Launchd;
using Axiom.Infrastructure.MacOS.Monitoring;
using Axiom.Infrastructure.Unix;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Ipc;
using Axiom.Infrastructure.Unix.Monitoring;
using Axiom.Service.Hosting.Dns;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Runtime.InteropServices;

namespace Axiom.Service;

/// <summary>
/// macOS wiring of the service (net10.0 target, executable <c>axiomd</c>): launchd manages the
/// process, so this is a plain console host; adapters come from Axiom.Infrastructure.MacOS.
/// </summary>
internal static class ServicePlatform
{
    private const string ServiceProcessName = "axiomd";

    public static bool TryRunCommand(string[] args, out int exitCode)
    {
        if (OperatingSystem.IsLinux())
        {
            return LinuxServicePlatform.TryRunCommand(args, out exitCode);
        }

        exitCode = 0;
        if (args.Length > 0 && args[0].StartsWith("--", StringComparison.Ordinal))
        {
            // Run from the desktop's administrator prompt: see ChildSignal.
            Axiom.Infrastructure.MacOS.Interop.ChildSignal.ReexecIfChildSignalIgnored(args);
        }

        if (args.Length > 0 &&
            string.Equals(args[0], "--install-service", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = new LaunchdServiceInstaller().Install(Environment.ProcessPath ?? string.Empty, Console.Out, Console.Error);
            return true;
        }

        if (args.Length > 0 &&
            string.Equals(args[0], "--uninstall-service", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = new LaunchdServiceInstaller().Uninstall(Console.Out, Console.Error);
            return true;
        }

        if (args.Length > 0 &&
            string.Equals(args[0], "--doctor", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = MacDoctor.Run(args, Console.Out);
            return true;
        }

        return false;
    }

    /// <summary>
    /// The machine data directory is 0700 root with 0600 files (filter/ 0755, rules.json 0644 for
    /// the extension). Applied on every daemon start so an older layout is tightened in place
    /// (the macOS counterpart of the Windows ProgramData ACL hardening).
    /// </summary>
    public static void HardenMachineState()
    {
        if (OperatingSystem.IsLinux())
        {
            LinuxServicePlatform.HardenMachineState();
            return;
        }

        if (!Environment.IsPrivilegedProcess)
        {
            return;
        }

        // First thing the daemon does, before any Console use, so no console stream keeps
        // launchd's descriptor of the log open (see AttachDaemonLog).
        AttachDaemonLog();

        var paths = MacServicePaths.Default;
        try
        {
            var changed = UnixDataDirectoryPermissions.Enforce(paths.MachineDataDirectory)
                .Concat(MacLogPermissions.Enforce(MacServicePaths.LogDirectory, MacServicePaths.LogFilePath))
                .ToList();
            if (changed.Count > 0)
            {
                Console.Error.WriteLine($"Data directory permissions: tightened {changed.Count} entries under {paths.MachineDataDirectory}.");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Data directory permissions: {exception.Message}");
        }
    }

    /// <summary>Network recovery baseline in the machine data root (<c>network-recovery.txt</c>, 0600).</summary>
    public static string RecoverySnapshotPath => OperatingSystem.IsLinux()
        ? LinuxServicePlatform.RecoverySnapshotPath
        : MacServicePaths.Default.RecoverySnapshotFile;

    /// <summary>
    /// After a snapshot lands in the machine data directory, re-assert 0700/0600 on it
    /// (the macOS counterpart of upstream's ProgramData re-hardening on capture).
    /// </summary>
    public static void HardenRecoverySnapshotLocation() => HardenMachineState();

    public static IPrivacyDnsPlatform CreateDefaultPrivacyDnsPlatform() =>
        OperatingSystem.IsMacOS()
            ? MacPrivacyDnsPlatform.Create(MacServicePaths.Default)
            : OperatingSystem.IsLinux()
                ? LinuxServicePlatform.CreateDefaultPrivacyDnsPlatform()
                : NullPrivacyDnsPlatform.Instance;

    public static void ConfigureServices(HostApplicationBuilder builder)
    {
        if (OperatingSystem.IsLinux())
        {
            LinuxServicePlatform.ConfigureServices(builder);
            return;
        }

        var paths = MacServicePaths.Default;
        builder.Services.AddSingleton(paths);
        builder.Services.AddSingleton<FilterStatus>();
        builder.Services.AddSingleton<FlowTable>();
        builder.Services.AddSingleton<FilterEventServer>();
        builder.Services.AddHostedService<FilterEventWorker>();
        builder.Services.AddSingleton<IConnectionSnapshotSource>(provider => MacConnectionSource.Create(
            provider.GetRequiredService<FlowTable>(),
            provider.GetRequiredService<FilterStatus>()));
        builder.Services.AddSingleton<MacFirewallPolicyAdapter>();
        builder.Services.AddSingleton<IFirewallPolicyAdapter>(provider => provider.GetRequiredService<MacFirewallPolicyAdapter>());
        builder.Services.AddSingleton<IOwnedRuleRecoveryAdapter>(provider => provider.GetRequiredService<MacFirewallPolicyAdapter>());
        builder.Services.AddSingleton<INetworkRecoveryDnsAdapter>(provider => MacDnsRecoveryAdapter.Create(
            provider.GetRequiredService<MacServicePaths>()));
        builder.Services.AddSingleton<IPrivacyDnsPlatform>(_ => CreateDefaultPrivacyDnsPlatform());
        builder.Services.AddSingleton<IIpcTransport>(provider => new UnixSocketIpcTransport(
            provider.GetRequiredService<MacServicePaths>(),
            provider.GetRequiredService<ProtectionSettingsStore>()));
    }

    private static DaemonLogFile? s_daemonLog;

    private static PosixSignalRegistration? s_reopenOnHangup;

    /// <summary>
    /// Under launchd (<c>AXIOM_SERVICE=1</c>, root) the daemon writes its own log instead of
    /// relying on launchd's <c>StandardOutPath</c> descriptor, which launchd keeps across a
    /// newsyslog rotation (every later line then went into the rotated, compressed, unlinked
    /// file). Console output and the console logger (created after this, at host build) go to a
    /// <see cref="DaemonLogFile"/> that reopens on SIGHUP (sent by newsyslog through the pid file)
    /// and on a detected rotation; fd 1/2 follow it for native output. Must run before the host is
    /// built so the console logger captures the redirected writer; called from HardenMachineState,
    /// which Program.cs runs before anything else of the service.
    /// </summary>
    private static void AttachDaemonLog()
    {
        if (s_daemonLog is not null || // HardenMachineState also runs after each recovery snapshot
            !OperatingSystem.IsMacOS() ||
            !Environment.IsPrivilegedProcess ||
            !string.Equals(Environment.GetEnvironmentVariable(LaunchdServiceInstaller.ServiceEnvironmentVariable), "1", StringComparison.Ordinal))
        {
            return;
        }

        try
        {
            var log = new DaemonLogFile(MacServicePaths.LogFilePath, TimeSpan.FromSeconds(1), redirectStandardStreams: true, announceReopen: true);
            Console.SetOut(log);
            Console.SetError(log);
            s_daemonLog = log;
            s_reopenOnHangup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, context =>
            {
                context.Cancel = true; // SIGHUP means "reopen the log", not "terminate".
                s_daemonLog?.Reopen();
            });
            DaemonLogFile.WritePidFile(LaunchdServiceInstaller.PidFilePath);
            AppDomain.CurrentDomain.ProcessExit += (_, _) => TryDeletePidFile();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            Console.Error.WriteLine($"Daemon log: {exception.Message}");
        }
    }

    private static void TryDeletePidFile()
    {
        try
        {
            if (File.Exists(LaunchdServiceInstaller.PidFilePath) &&
                string.Equals(File.ReadAllText(LaunchdServiceInstaller.PidFilePath).Trim(), Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal))
            {
                File.Delete(LaunchdServiceInstaller.PidFilePath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    // --- NetworkRecoveryCommand platform hooks (offline administrator recovery, `sudo axiomd --recover-network`) ---

    /// <summary>axiomd is a console executable; its output already reaches the terminal.</summary>
    public static void AttachParentConsole()
    {
    }

    public static bool IsAdministrator() => Environment.IsPrivilegedProcess;

    public static bool IsServiceProcessRunning()
    {
        var runningProcesses = System.Diagnostics.Process.GetProcessesByName(ServiceProcessName);
        try
        {
            return runningProcesses.Any(process => process.Id != Environment.ProcessId);
        }
        finally
        {
            foreach (var process in runningProcesses)
            {
                process.Dispose();
            }
        }
    }

    public static (INetworkRecoveryDnsAdapter Dns, IOwnedRuleRecoveryAdapter Firewall, IDisposable? Owner) CreateRecoveryAdapters()
    {
        if (OperatingSystem.IsLinux())
        {
            return LinuxServicePlatform.CreateRecoveryAdapters();
        }

        var paths = MacServicePaths.Default;
        var firewall = new MacFirewallPolicyAdapter(paths, new FilterStatus());
        return (MacDnsRecoveryAdapter.Create(paths), firewall, firewall);
    }

    public static string CurrentActor()
    {
        var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
        return string.IsNullOrWhiteSpace(sudoUser) ? Environment.UserName : sudoUser.Trim();
    }
}
