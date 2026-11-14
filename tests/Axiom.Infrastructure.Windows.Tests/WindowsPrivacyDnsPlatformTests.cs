// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Windows.Dns;
using Axiom.Service.Hosting.Dns;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class WindowsPrivacyDnsPlatformTests
{
    [Fact]
    public void No_upstream_warning_is_the_text_upstream_shows_on_windows()
    {
        IPrivacyDnsPlatform platform = new WindowsPrivacyDnsPlatform(() => false);

        Assert.Equal(
            "No non-loopback Windows DNS server was found; using encrypted DoH fallback upstream DNS. " +
            "Set an explicit upstream address if this network requires a local resolver.",
            platform.NoUpstreamWarning);
        Assert.False(platform.RediscoversUpstreams);
        Assert.Null(platform.OnResolverStarted(53));
    }
}
