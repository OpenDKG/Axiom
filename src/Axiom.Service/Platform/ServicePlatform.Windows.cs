// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Security.Principal;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Windows.Dns;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Infrastructure.Windows.Ipc;
using Axiom.Infrastructure.Windows.Network;
using Axiom.Service.Hosting.Dns;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Axiom.Service;

/// <summary>Windows wiring of the service (net10.0-windows target): unchanged behaviour.</summary>
internal static class ServicePlatform
{
    private const string ServiceProcessName = "Axiom.Service";

    public static bool TryRunCommand(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length > 0 &&
            string.Equals(args[0], "--install-service", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                exitCode = ServiceInstaller.Install(ReadOption(args, "--allowed-sid"));
            }
            catch (Exception exception)
            {
                WriteInstallFailure(exception);
                exitCode = 8;
            }

            return true;
        }

        if (args.Length > 0 &&
            string.Equals(args[0], "--uninstall-service", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = ServiceInstaller.Uninstall();
            return true;
        }

        return false;
    }

    /// <summary>
    /// The service owns machine-wide state. Harden ProgramData and make sure the registered image
    /// is the protected copy before anything reads settings or migrates data.
    /// </summary>
    public static void HardenMachineState()
    {
        if (MachineStateSecurity.IsRunningAsSystem())
        {
            MachineStateSecurity.HardenProgramData();
            ServiceImageProtection.EnsureProtectedImage();
        }
    }

    /// <summary>Machine-wide location written by the elevated service and the recovery command.</summary>
    public static string RecoverySnapshotPath => NetworkRecoverySnapshotStore.DefaultPath;

    public static IPrivacyDnsPlatform CreateDefaultPrivacyDnsPlatform() =>
        new WindowsPrivacyDnsPlatform(PrivacyDnsFailSafe.RestoreIfNeeded);

    public static void ConfigureServices(HostApplicationBuilder builder)
    {
        builder.Services.AddWindowsService(options => options.ServiceName = ServiceInfo.ServiceName);

        builder.Services.AddSingleton<IConnectionSnapshotSource>(_ => new IpHelperConnectionSource());
        builder.Services.AddSingleton<WindowsFirewallPolicyAdapter>();
        builder.Services.AddSingleton<IFirewallPolicyAdapter>(provider => provider.GetRequiredService<WindowsFirewallPolicyAdapter>());
        builder.Services.AddSingleton<IOwnedRuleRecoveryAdapter>(provider => provider.GetRequiredService<WindowsFirewallPolicyAdapter>());
        builder.Services.AddSingleton<INetworkRecoveryDnsAdapter, WindowsDnsRecoveryAdapter>();
        builder.Services.AddSingleton<IPrivacyDnsPlatform>(_ => CreateDefaultPrivacyDnsPlatform());
        builder.Services.AddSingleton<IIpcTransport>(_ => new NamedPipeIpcTransport(IpcPipe.Name, ServiceInfo.ResolveAllowedSid));
    }

    // --- NetworkRecoveryCommand platform hooks (offline administrator recovery) ---

    private const uint AttachParentProcess = 0xFFFFFFFF;

    /// <summary>Attaches the console of the parent process so a WinExe can print its plan.</summary>
    public static void AttachParentConsole() => _ = AttachConsole(AttachParentProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint processId);

    public static bool IsAdministrator() => ServiceInstaller.IsAdministrator();

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
        var firewall = new WindowsFirewallPolicyAdapter();
        return (new WindowsDnsRecoveryAdapter(), firewall, firewall);
    }

    public static string CurrentActor()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.Name ?? "administrator";
        }
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException)
        {
            return "administrator";
        }
    }

    private static string? ReadOption(string[] arguments, string name)
    {
        for (var index = 0; index < arguments.Length - 1; index++)
        {
            if (string.Equals(arguments[index], name, StringComparison.OrdinalIgnoreCase))
            {
                return arguments[index + 1];
            }
        }

        return null;
    }

    private static void WriteInstallFailure(Exception exception)
    {
        try
        {
            var path = Path.Combine(Path.GetTempPath(), "axiom-service-install-error.log");
            File.WriteAllText(path, $"{DateTimeOffset.UtcNow:O}{Environment.NewLine}{exception}");
        }
        catch (Exception writeFailure) when (writeFailure is IOException or UnauthorizedAccessException)
        {
        }
    }
}
