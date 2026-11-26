// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

namespace Axiom.Service.Tests;

public sealed class ServiceInstallerSidTests
{
    private const string StandardUser = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private const string ApprovingAdmin = "S-1-5-21-1111111111-2222222222-3333333333-500";

    [Fact]
    public void Caller_sid_is_bound_even_when_a_different_administrator_elevated()
    {
        var decision = ServiceInstaller.ResolveAllowedSid(StandardUser, ApprovingAdmin, interactiveSid: null);

        Assert.Equal(StandardUser, decision.Sid);
        Assert.Equal("caller", decision.Source);
        Assert.Null(decision.Warning);
        Assert.Null(decision.Error);
    }

    [Theory]
    [InlineData("not-a-sid")]
    [InlineData("S-1-5-21-1001 --other")]
    [InlineData("S-1")]
    public void Malformed_caller_sid_is_rejected_instead_of_falling_back(string requested)
    {
        var decision = ServiceInstaller.ResolveAllowedSid(requested, ApprovingAdmin, StandardUser);

        Assert.Null(decision.Sid);
        Assert.NotNull(decision.Error);
    }

    [Fact]
    public void Fallback_to_the_elevated_identity_warns_when_it_differs_from_the_interactive_user()
    {
        var decision = ServiceInstaller.ResolveAllowedSid(null, ApprovingAdmin, StandardUser);

        Assert.Equal(ApprovingAdmin, decision.Sid);
        Assert.Equal("elevated-fallback", decision.Source);
        Assert.NotNull(decision.Warning);
        Assert.Contains(StandardUser, decision.Warning, StringComparison.Ordinal);
        Assert.Contains("--allowed-sid", decision.Warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Fallback_is_quiet_when_the_elevated_identity_is_the_interactive_user()
    {
        var decision = ServiceInstaller.ResolveAllowedSid("  ", StandardUser, StandardUser);

        Assert.Equal(StandardUser, decision.Sid);
        Assert.Equal("elevated-fallback", decision.Source);
        Assert.Null(decision.Warning);
    }
}
