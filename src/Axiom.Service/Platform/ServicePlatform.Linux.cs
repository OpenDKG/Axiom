// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Linux;
using Axiom.Infrastructure.Linux.Diagnostics;
using Axiom.Infrastructure.Linux.Dns;
using Axiom.Infrastructure.Linux.Firewall;
using Axiom.Infrastructure.Linux.Monitoring;
using Axiom.Infrastructure.Linux.Nft;
using Axiom.Infrastructure.Linux.Systemd;
using Axiom.Infrastructure.Unix;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Ipc;
using Axiom.Infrastructure.Unix.Monitoring;
using Axiom.Service.Hosting.Dns;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Axiom.Service;

/// <summary>
/// Linux wiring of the service (net10.0 target, executable <c>axiomd</c>, systemd unit
/// <c>axiomd.service</c>): adapters come from Axiom.Infrastructure.Linux, the IPC socket from
/// Axiom.Infrastructure.Unix. <see cref="ServicePlatform"/> forwards here when
/// <see cref="OperatingSystem.IsLinux"/>; the macOS paths in ServicePlatform.Unix.cs are untouched.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
internal static class LinuxServicePlatform
{
    public static bool TryRunCommand(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length == 0)
        {
            return false;
        }

        if (string.Equals(args[0], "--install-service", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = new SystemdServiceInstaller().Install(
                Environment.ProcessPath ?? string.Empty, Console.Out, Console.Error, SystemdServiceInstaller.IsDryRun(args));
            return true;
        }

        if (string.Equals(args[0], "--uninstall-service", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = new SystemdServiceInstaller().Uninstall(Console.Out, Console.Error, SystemdServiceInstaller.IsDryRun(args));
            return true;
        }

        if (string.Equals(args[0], "--doctor", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = LinuxDoctor.Run(args, Console.Out);
            return true;
        }

        return false;
    }

    /// <summary>0700 root data directory with 0600 files (the Linux counterpart of the ProgramData ACL hardening).</summary>
    public static void HardenMachineState()
    {
        if (!Environment.IsPrivilegedProcess)
        {
            return;
        }

        var paths = LinuxServicePaths.Default;
        try
        {
            var changed = UnixDataDirectoryPermissions.Enforce(paths.MachineDataDirectory)
                .Concat(UnixLogPermissions.EnforceDirectory(LinuxServicePaths.LogDirectory))
                .ToList();
            if (changed.Count > 0)
            {
                Console.Error.WriteLine($"Data directory permissions: tightened {changed.Count} entries under {paths.MachineDataDirectory} and {LinuxServicePaths.LogDirectory}.");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Data directory permissions: {exception.Message}");
        }
    }

    public static string RecoverySnapshotPath => LinuxServicePaths.Default.RecoverySnapshotFile;

    public static IPrivacyDnsPlatform CreateDefaultPrivacyDnsPlatform() =>
        LinuxPrivacyDnsPlatform.Create(LinuxServicePaths.Default);

    public static void ConfigureServices(HostApplicationBuilder builder)
    {
        var paths = LinuxServicePaths.Default;
        builder.Services.AddSingleton(paths);
        builder.Services.AddSingleton<UnixServicePaths>(paths);
        // Same event plumbing as macOS (FilterStatus/FlowTable/FilterEventServer); the nftables
        // engine feeds it in-process through FilterEventPipe instead of a socket client.
        builder.Services.AddSingleton<FilterStatus>();
        builder.Services.AddSingleton<FlowTable>();
        builder.Services.AddSingleton<FilterEventServer>();
        builder.Services.AddSingleton<FilterEventPipe>();
        builder.Services.AddSingleton<IConnectionSnapshotSource>(provider => LinuxConnectionSource.Create(
            provider.GetRequiredService<FlowTable>()));
        builder.Services.AddSingleton(provider => LinuxEnforcement.CreateAdapter(
            provider.GetRequiredService<LinuxServicePaths>(),
            provider.GetRequiredService<FilterEventPipe>()));
        builder.Services.AddSingleton<IFirewallPolicyAdapter>(provider => provider.GetRequiredService<NftFirewallPolicyAdapter>());
        builder.Services.AddSingleton<IOwnedRuleRecoveryAdapter>(provider => provider.GetRequiredService<NftFirewallPolicyAdapter>());
        builder.Services.AddHostedService<NftEnforcementWorker>();
        builder.Services.AddSingleton<INetworkRecoveryDnsAdapter>(_ => LinuxDnsRecoveryAdapter.Create());
        builder.Services.AddSingleton<IPrivacyDnsPlatform>(_ => CreateDefaultPrivacyDnsPlatform());
        builder.Services.AddSingleton<IIpcTransport>(provider => new UnixSocketIpcTransport(
            provider.GetRequiredService<LinuxServicePaths>(),
            uid => PeerAuthorization.Decide(
                uid,
                PeerPolicy.FromSettings(provider.GetRequiredService<ProtectionSettingsStore>().Load(), UnixAccountRange.Linux),
                UnixAccountRange.Linux)));
        builder.Services.AddHostedService<SystemdReadyNotifier>();
    }

    public static (INetworkRecoveryDnsAdapter Dns, IOwnedRuleRecoveryAdapter Firewall, IDisposable? Owner) CreateRecoveryAdapters()
    {
        var firewall = LinuxEnforcement.CreateAdapter(LinuxServicePaths.Default, NullFilterEventSink.Instance);
        return (LinuxDnsRecoveryAdapter.Create(), firewall, firewall);
    }
}
