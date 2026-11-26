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

    // PipeSecurityFactory grants the bound SID ReadWrite on the service pipe, so a group SID
    // would open the pipe to every member of that group.
    [Theory]
    [InlineData("S-1-1-0")] // Everyone
    [InlineData("S-1-2-0")] // Local
    [InlineData("S-1-5-4")] // Interactive
    [InlineData("S-1-5-11")] // Authenticated Users
    [InlineData("S-1-5-18")] // LocalSystem
    [InlineData("S-1-5-32-544")] // BUILTIN\Administrators
    [InlineData("S-1-5-32-545")] // BUILTIN\Users
    [InlineData("S-1-15-2-1")] // All Application Packages
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333")] // domain identifier, no account RID
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-498")] // Enterprise Read-only Domain Controllers
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-512")] // Domain Admins
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-513")] // Domain Users
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-514")] // Domain Guests
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-515")] // Domain Computers
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-519")] // Enterprise Admins
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-522")] // Cloneable Domain Controllers
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-525")] // Protected Users
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-553")] // RAS and IAS Servers
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-572")] // Denied RODC Password Replication
    [InlineData("S-1-5-21-1111111111-2222222222-99999999999-1001")] // sub-authority beyond 32 bits
    public void Group_and_non_account_caller_sids_are_rejected(string requested)
    {
        var decision = ServiceInstaller.ResolveAllowedSid(requested, ApprovingAdmin, StandardUser);

        Assert.Null(decision.Sid);
        Assert.NotNull(decision.Error);
    }

    [Theory]
    [InlineData(StandardUser)]
    [InlineData(ApprovingAdmin)]
    [InlineData("S-1-5-21-4294967295-1-2-5130")]
    public void Local_and_domain_account_sids_are_accepted(string requested)
    {
        var decision = ServiceInstaller.ResolveAllowedSid(requested, ApprovingAdmin, interactiveSid: null);

        Assert.Equal(requested, decision.Sid);
        Assert.Null(decision.Error);
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
