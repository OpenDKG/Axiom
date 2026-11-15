// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.UI.Services;
using Axiom.UI.ViewModels;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class PrivacyOverviewIntegrationTests
{
    [Fact]
    public void Overview_wires_privacy_shield_and_navigation_callback()
    {
        using var monitor = new ConnectionMonitor(new EmptySource());
        using var security = new SecurityViewModel();
        using var agents = new AgentsViewModel(security);
        using var privacy = new PrivacyShieldViewModel(serviceMode: false);
        var navigated = false;

        using var overview = new OverviewViewModel(
            monitor,
            agents,
            privacy,
            openPrivacyShield: () => navigated = true);

        Assert.True(overview.HasPrivacyShield);
        Assert.Same(privacy, overview.PrivacyShield);
        Assert.Equal("0", privacy.RuleCountText);
        Assert.Equal("0", privacy.AllowedCountText);
        Assert.Equal("0", privacy.BlockedCountText);
        Assert.Equal("0", privacy.ErrorsCountText);

        overview.OpenPrivacyShieldCommand.Execute(null);
        Assert.True(navigated);
    }

    private sealed class EmptySource : IConnectionSnapshotSource
    {
        public string Name => "test";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(5);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "test",
            });
    }
}
