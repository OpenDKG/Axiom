// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Persistence;
using Axiom.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// Elevated helper mode: register or remove the Windows service, then exit. This runs once, from a
// UAC prompt started by the desktop app, and is the only path that needs administrator rights.
if (args.Length > 0 &&
    string.Equals(args[0], "--install-service", StringComparison.OrdinalIgnoreCase))
{
    return ServiceInstaller.Install(ReadOption(args, "--allowed-sid"));
}

if (args.Length > 0 &&
    string.Equals(args[0], "--uninstall-service", StringComparison.OrdinalIgnoreCase))
{
    return ServiceInstaller.Uninstall();
}

Axiom.Persistence.LegacyDataMigration.Migrate();

ServiceInfo.MarkStarted();

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = ServiceInfo.ServiceName);

builder.Services.AddSingleton<ConnectionSnapshotCache>();
builder.Services.AddSingleton(new HistoryStore(DatabasePaths.ResolveForCurrentProcess()));
builder.Services.AddSingleton<WindowsFirewallPolicyAdapter>();
builder.Services.AddSingleton<IFirewallPolicyAdapter>(provider => provider.GetRequiredService<WindowsFirewallPolicyAdapter>());
builder.Services.AddSingleton<FirewallRuleCoordinator>();
builder.Services.AddSingleton(new ProtectionSettingsStore());
builder.Services.AddSingleton<ProtectionController>();
builder.Services.AddHostedService<ProtectionWorker>();
builder.Services.AddSingleton<PrivacyShieldSettingsStore>();
builder.Services.AddSingleton<ThreatShareController>();
builder.Services.AddSingleton<PrivacyShieldController>();
builder.Services.AddHostedService<PrivacyShieldWorker>();
builder.Services.AddHostedService<ThreatShareWorker>();

builder.Services.AddSingleton<MonitoringWorker>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<MonitoringWorker>());

builder.Services.AddSingleton<HistoryWriter>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<HistoryWriter>());

builder.Services.AddHostedService<ThroughputRecorderWorker>();

builder.Services.AddSingleton<PipeServerWorker>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<PipeServerWorker>());

// Establish the persisted consent before the first request can read the capabilities.
ProtectionWriteConsent.Set(new ProtectionSettingsStore().Load().Enabled);

var host = builder.Build();
await host.RunAsync();
return 0;

static string? ReadOption(string[] arguments, string name)
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
