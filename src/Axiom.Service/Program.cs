// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Persistence;
using Axiom.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// Explicit administrator recovery when the service or desktop cannot run. Dry run unless --apply.
if (args.Length > 0 &&
    string.Equals(args[0], "--recover-network", StringComparison.OrdinalIgnoreCase))
{
    return NetworkRecoveryCommand.Run(args);
}

// Elevated helper mode: register or remove the service (Windows service / macOS launchd daemon),
// then exit. This runs once, from an elevation prompt started by the desktop app, and is the only
// path that needs administrator rights.
if (ServicePlatform.TryRunCommand(args, out var exitCode))
{
    return exitCode;
}

// The service owns machine-wide state. Harden it (Windows: ProgramData ACL and the protected
// service image; macOS: 0700/0600 modes of the machine data root) before anything reads settings
// or migrates data.
ServicePlatform.HardenMachineState();

Axiom.Persistence.LegacyDataMigration.Migrate();

ServiceInfo.MarkStarted();

var builder = Host.CreateApplicationBuilder(args);

ServicePlatform.ConfigureServices(builder);

builder.Services.AddSingleton<ConnectionSnapshotCache>();
builder.Services.AddSingleton(new HistoryStore(DatabasePaths.ResolveForCurrentProcess()));
builder.Services.AddSingleton(provider => new NetworkRecoveryController(
    provider.GetRequiredService<INetworkRecoveryDnsAdapter>(),
    provider.GetRequiredService<IOwnedRuleRecoveryAdapter>(),
    () => ProtectionWriteConsent.IsServiceHost,
    () => provider.GetRequiredService<ProtectionSettingsStore>().Load().Enabled,
    ServicePlatform.RecoverySnapshotPath,
    provider.GetRequiredService<HistoryStore>(),
    provider.GetRequiredService<ILogger<NetworkRecoveryController>>(),
    isLoopbackResolverExpected: () => provider.GetRequiredService<PrivacyShieldController>().IsEnabled));
builder.Services.AddHostedService<NetworkRecoveryWorker>();
builder.Services.AddSingleton<FirewallRuleCoordinator>();
builder.Services.AddSingleton(new ProtectionSettingsStore());
builder.Services.AddSingleton<ProtectionController>();
ServicePlatform.ConfigureAgentEnforcement(builder);
builder.Services.AddHostedService<ProtectionWorker>();
builder.Services.AddSingleton<PrivacyShieldSettingsStore>();
builder.Services.AddSingleton<ThreatShareController>();
builder.Services.AddSingleton<PrivacyShieldController>();
builder.Services.AddHostedService<PrivacyShieldWorker>();
builder.Services.AddHostedService<ThreatShareWorker>();
builder.Services.AddHostedService<ProcessSpawnAuditWorker>();

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
