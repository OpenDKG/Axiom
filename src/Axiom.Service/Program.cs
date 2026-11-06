// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Persistence;
using Axiom.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

Axiom.Persistence.LegacyDataMigration.Migrate();

ServiceInfo.MarkStarted();

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = ServiceInfo.ServiceName);

builder.Services.AddSingleton<ConnectionSnapshotCache>();
builder.Services.AddSingleton(new HistoryStore(DatabasePaths.ResolveForCurrentProcess()));
builder.Services.AddSingleton<WindowsFirewallPolicyAdapter>();
builder.Services.AddSingleton<IFirewallPolicyAdapter>(provider => provider.GetRequiredService<WindowsFirewallPolicyAdapter>());
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
