// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Infrastructure.Windows.Network;
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

// Elevated helper mode: register or remove the Windows service, then exit. This runs once, from a
// UAC prompt started by the desktop app, and is the only path that needs administrator rights.
if (args.Length > 0 &&
    string.Equals(args[0], "--install-service", StringComparison.OrdinalIgnoreCase))
{
    try
    {
        return ServiceInstaller.Install(ReadOption(args, "--allowed-sid"));
    }
    catch (Exception exception)
    {
        WriteInstallFailure(exception);
        return 8;
    }
}

if (args.Length > 0 &&
    string.Equals(args[0], "--uninstall-service", StringComparison.OrdinalIgnoreCase))
{
    return ServiceInstaller.Uninstall();
}

// The service owns machine-wide state. Harden ProgramData and make sure the registered image is
// the protected copy before anything reads settings or migrates data.
if (MachineStateSecurity.IsRunningAsSystem())
{
    MachineStateSecurity.HardenProgramData();
    ServiceImageProtection.EnsureProtectedImage();
}

Axiom.Persistence.LegacyDataMigration.Migrate();

ServiceInfo.MarkStarted();

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = ServiceInfo.ServiceName);

builder.Services.AddSingleton<ConnectionSnapshotCache>();
builder.Services.AddSingleton(new HistoryStore(DatabasePaths.ResolveForCurrentProcess()));
builder.Services.AddSingleton<WindowsFirewallPolicyAdapter>();
builder.Services.AddSingleton<IFirewallPolicyAdapter>(provider => provider.GetRequiredService<WindowsFirewallPolicyAdapter>());
builder.Services.AddSingleton<IOwnedRuleRecoveryAdapter>(provider => provider.GetRequiredService<WindowsFirewallPolicyAdapter>());
builder.Services.AddSingleton<INetworkRecoveryDnsAdapter, WindowsDnsRecoveryAdapter>();
builder.Services.AddSingleton(provider => new NetworkRecoveryController(
    provider.GetRequiredService<INetworkRecoveryDnsAdapter>(),
    provider.GetRequiredService<IOwnedRuleRecoveryAdapter>(),
    () => ProtectionWriteConsent.IsServiceHost,
    () => provider.GetRequiredService<ProtectionSettingsStore>().Load().Enabled,
    NetworkRecoverySnapshotStore.DefaultPath,
    provider.GetRequiredService<HistoryStore>(),
    provider.GetRequiredService<ILogger<NetworkRecoveryController>>(),
    isLoopbackResolverExpected: () => provider.GetRequiredService<PrivacyShieldController>().IsEnabled));
builder.Services.AddHostedService<NetworkRecoveryWorker>();
builder.Services.AddSingleton<FirewallRuleCoordinator>();
builder.Services.AddSingleton(new ProtectionSettingsStore());
builder.Services.AddSingleton<ProtectionController>();
builder.Services.AddSingleton<EnforcementController>();
builder.Services.AddSingleton(provider => new AgentFirewallEnforcer(
    provider.GetRequiredService<FirewallRuleCoordinator>(),
    provider.GetRequiredService<EnforcementController>().ReceiptJournal));
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

static void WriteInstallFailure(Exception exception)
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
