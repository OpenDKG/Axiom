// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Firewall;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.MacOS;
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
    public static bool TryRunCommand(string[] args, out int exitCode)
    {
        exitCode = 0;
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

        return false;
    }

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
        builder.Services.AddSingleton<IPrivacyDnsPlatform>(_ => CreateDefaultPrivacyDnsPlatform());
        builder.Services.AddSingleton<IIpcTransport>(provider => new UnixSocketIpcTransport(provider.GetRequiredService<MacServicePaths>()));
    }
}
