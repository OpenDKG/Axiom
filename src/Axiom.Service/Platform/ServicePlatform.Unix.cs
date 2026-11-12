// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.MacOS;
using Axiom.Infrastructure.MacOS.Diagnostics;
using Axiom.Infrastructure.MacOS.Dns;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Ipc;
using Axiom.Infrastructure.MacOS.Launchd;
using Axiom.Infrastructure.MacOS.Monitoring;
using Axiom.Service.Hosting.Dns;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

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
        if (!Environment.IsPrivilegedProcess)
        {
            return;
        }

        var paths = MacServicePaths.Default;
        try
        {
            var changed = MacDataDirectoryPermissions.Enforce(paths.MachineDataDirectory);
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
    public static string RecoverySnapshotPath => MacServicePaths.Default.RecoverySnapshotFile;

    /// <summary>
    /// After a snapshot lands in the machine data directory, re-assert 0700/0600 on it
    /// (the macOS counterpart of upstream's ProgramData re-hardening on capture).
    /// </summary>
    public static void HardenRecoverySnapshotLocation() => HardenMachineState();

    public static IPrivacyDnsPlatform CreateDefaultPrivacyDnsPlatform() =>
        OperatingSystem.IsMacOS()
            ? MacPrivacyDnsPlatform.Create(MacServicePaths.Default)
            : NullPrivacyDnsPlatform.Instance;

    public static void ConfigureServices(HostApplicationBuilder builder)
    {
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
