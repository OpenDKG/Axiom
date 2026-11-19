// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

namespace Axiom.Service.Tests;

public sealed class PrivacyDnsPlatformWiringTests
{
    /// <summary>
    /// Upstream v0.23.3 persists adapter DNS from the service. The production factory must pass
    /// all three helpers (<see cref="PrivacyDnsFailSafe.RestoreIfNeeded"/>,
    /// <see cref="MachineStateSecurity.IsRunningAsSystem"/> and
    /// <see cref="PrivacyDnsFailSafe.EnsureAdapterPointed"/>); with only the restore delegate the
    /// platform silently reports <c>SupportsAdapterDnsPersistence = false</c> and never points the
    /// adapter at the loopback resolver.
    /// </summary>
    [Fact]
    public void Default_windows_privacy_dns_platform_has_the_service_helpers()
    {
        var platform = ServicePlatform.CreateDefaultPrivacyDnsPlatform();

        Assert.True(platform.SupportsAdapterDnsPersistence);
    }
}
