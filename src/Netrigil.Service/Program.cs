// SPDX-License-Identifier: GPL-3.0-or-later
using Netrigil.Infrastructure.Windows.Firewall;
using Netrigil.Persistence;
using Netrigil.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

ServiceInfo.MarkStarted();

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = ServiceInfo.ServiceName);

builder.Services.AddSingleton<ConnectionSnapshotCache>();
builder.Services.AddSingleton(new HistoryStore(DatabasePaths.ResolveForCurrentProcess()));
builder.Services.AddSingleton<WindowsFirewallPolicyAdapter>();

builder.Services.AddSingleton<MonitoringWorker>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<MonitoringWorker>());

builder.Services.AddSingleton<HistoryWriter>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<HistoryWriter>());

builder.Services.AddSingleton<PipeServerWorker>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<PipeServerWorker>());

var host = builder.Build();
await host.RunAsync();
