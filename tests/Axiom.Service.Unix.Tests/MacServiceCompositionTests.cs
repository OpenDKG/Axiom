// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Axiom.Infrastructure.MacOS;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.Unix;
using Axiom.Infrastructure.Unix.Filter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service.Unix.Tests;

/// <summary>
/// The macOS daemon's container, built on any Unix host. A registered type whose constructor
/// needs a service nobody registered only fails when launchd starts axiomd on a Mac (1.4.8:
/// FilterEventServer took UnixServicePaths while only MacServicePaths was registered), so the
/// whole platform composition is validated here instead.
/// </summary>
public sealed class MacServiceCompositionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "axiom-mac-composition-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void Mac_platform_services_validate_on_build()
    {
        using var provider = BuildProvider();

        Assert.NotNull(provider);
    }

    [Fact]
    public void Mac_platform_singletons_and_hosted_services_resolve()
    {
        using var provider = BuildProvider();
        var paths = provider.GetRequiredService<MacServicePaths>();

        Assert.Same(paths, provider.GetRequiredService<UnixServicePaths>());
        Assert.NotNull(provider.GetRequiredService<FilterEventServer>());
        Assert.NotNull(provider.GetRequiredService<MacFirewallPolicyAdapter>());
        Assert.Contains(provider.GetServices<IHostedService>(), service => service is FilterEventWorker);
    }

    private ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.ClearProviders());
        // Registered by Program.cs for every platform; the IPC transport factory reads it.
        services.AddSingleton(new ProtectionSettingsStore());
        ServicePlatform.ConfigureMacServices(services, MacServicePaths.ForRoot(_root));

        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
    }
}
