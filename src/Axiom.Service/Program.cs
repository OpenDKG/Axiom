// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Firewall;
using Axiom.Core.Platform;
using Axiom.Persistence;
using Axiom.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

#if WINDOWS
using Axiom.Infrastructure.Windows;
#else
using Axiom.Infrastructure.Linux;
#endif

// Windows user data may still live under the old product name; the migration is Windows-only
// because no Linux build ever shipped under the old name.
if (OperatingSystem.IsWindows())
{
    Axiom.Persistence.LegacyDataMigration.Migrate();
}
ServiceInfo.MarkStarted();

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

#if WINDOWS
builder.Services.AddWindowsService(options => options.ServiceName = ServiceInfo.ServiceName);
builder.Services.AddSingleton<IServicePlatform, WindowsServicePlatform>();
#else
builder.Services.AddSingleton<IServicePlatform, LinuxServicePlatform>();
#endif

builder.Services.AddSingleton<ConnectionSnapshotCache>();
builder.Services.AddSingleton(new HistoryStore(DatabasePaths.ResolveForCurrentProcess()));
builder.Services.AddSingleton<IFirewallPolicyAdapter>(
    provider => provider.GetRequiredService<IServicePlatform>().CreateFirewallAdapter());
builder.Services.AddSingleton<FirewallRuleCoordinator>();
builder.Services.AddSingleton<PrivacyShieldSettingsStore>();
builder.Services.AddSingleton<PrivacyShieldController>();
builder.Services.AddHostedService<PrivacyShieldWorker>();

builder.Services.AddSingleton<MonitoringWorker>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<MonitoringWorker>());

builder.Services.AddSingleton<HistoryWriter>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<HistoryWriter>());

builder.Services.AddSingleton<PipeServerWorker>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<PipeServerWorker>());

var host = builder.Build();
await host.RunAsync();
