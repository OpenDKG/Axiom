// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Windows.Dns;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Infrastructure.Windows.IpHelper;
using Axiom.Infrastructure.Windows.Ipc;
using Axiom.Service.Hosting.Dns;
using Axiom.Service.Hosting.Ipc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Axiom.Service;

/// <summary>Windows wiring of the service (net10.0-windows target): unchanged behaviour.</summary>
internal static class ServicePlatform
{
    public static bool TryRunCommand(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length > 0 &&
            string.Equals(args[0], "--install-service", StringComparison.OrdinalIgnoreCase))
        {
            exitCode = ServiceInstaller.Install(ReadOption(args, "--allowed-sid"));
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

    public static IPrivacyDnsPlatform CreateDefaultPrivacyDnsPlatform() =>
        new WindowsPrivacyDnsPlatform(PrivacyDnsFailSafe.RestoreIfNeeded);

    public static void ConfigureServices(HostApplicationBuilder builder)
    {
        builder.Services.AddWindowsService(options => options.ServiceName = ServiceInfo.ServiceName);

        builder.Services.AddSingleton<IConnectionSnapshotSource>(_ => new IpHelperConnectionSource());
        builder.Services.AddSingleton<WindowsFirewallPolicyAdapter>();
        builder.Services.AddSingleton<IFirewallPolicyAdapter>(provider => provider.GetRequiredService<WindowsFirewallPolicyAdapter>());
        builder.Services.AddSingleton<IPrivacyDnsPlatform>(_ => CreateDefaultPrivacyDnsPlatform());
        builder.Services.AddSingleton<IIpcTransport>(_ => new NamedPipeIpcTransport(IpcPipe.Name, ServiceInfo.ResolveAllowedSid));
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
}
