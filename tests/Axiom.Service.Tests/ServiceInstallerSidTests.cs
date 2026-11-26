// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class ServiceInstallerSidTests
{
    private const string StandardUser = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private const string ApprovingAdmin = "S-1-5-21-1111111111-2222222222-3333333333-500";
    private const string EntraUser = "S-1-12-1-1111111111-2222222222-3333333333-444444444";
    private const string CustomDomainGroup = "S-1-5-21-1111111111-2222222222-3333333333-1604";
    private const string ServiceAccount = "S-1-5-18";

    /// <summary>Stands in for LookupAccountSid: what Windows would report for each test SID.</summary>
    private static SidNameUse? FakeLookup(string sid) => sid switch
    {
        StandardUser or ApprovingAdmin or EntraUser => SidNameUse.User,
        CustomDomainGroup or "S-1-12-1-5-6-7-8" => SidNameUse.Group,
        "S-1-5-32-544" or "S-1-5-32-545" => SidNameUse.Alias,
        "S-1-1-0" or "S-1-5-4" or "S-1-5-11" or "S-1-5-18" => SidNameUse.WellKnownGroup,
        "S-1-5-21-1111111111-2222222222-3333333333" => SidNameUse.Domain,
        "S-1-5-21-1111111111-2222222222-3333333333-2001" => SidNameUse.Computer,
        _ => null,
    };

    [Fact]
    public void Caller_sid_is_bound_even_when_a_different_administrator_elevated()
    {
        var decision = ServiceInstaller.ResolveAllowedSid(StandardUser, ApprovingAdmin, interactiveSid: null, FakeLookup);

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
        var decision = ServiceInstaller.ResolveAllowedSid(requested, ApprovingAdmin, StandardUser, _ => SidNameUse.User);

        Assert.Null(decision.Sid);
        Assert.NotNull(decision.Error);
    }

    // PipeSecurityFactory grants the bound SID ReadWrite on the service pipe, so a group SID
    // would open the pipe to every member of that group.
    [Theory]
    [InlineData("S-1-1-0")] // Everyone (well-known group)
    [InlineData("S-1-5-4")] // Interactive (well-known group)
    [InlineData("S-1-5-11")] // Authenticated Users (well-known group)
    [InlineData("S-1-5-18")] // LocalSystem (well-known group)
    [InlineData("S-1-5-32-544")] // BUILTIN\Administrators (alias)
    [InlineData("S-1-5-32-545")] // BUILTIN\Users (alias)
    [InlineData(CustomDomainGroup)] // custom group with an ordinary RID
    [InlineData("S-1-12-1-5-6-7-8")] // Entra ID group
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333")] // domain
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-2001")] // computer
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-9999")] // cannot be resolved
    public void Caller_sids_that_do_not_resolve_to_a_user_are_rejected(string requested)
    {
        var decision = ServiceInstaller.ResolveAllowedSid(requested, ApprovingAdmin, StandardUser, FakeLookup);

        Assert.Null(decision.Sid);
        Assert.NotNull(decision.Error);
    }

    [Theory]
    [InlineData(StandardUser)]
    [InlineData(ApprovingAdmin)]
    [InlineData(EntraUser)]
    public void Local_domain_and_entra_user_sids_are_accepted(string requested)
    {
        var decision = ServiceInstaller.ResolveAllowedSid(requested, ApprovingAdmin, interactiveSid: null, FakeLookup);

        Assert.Equal(requested, decision.Sid);
        Assert.Null(decision.Error);
    }

    [Theory]
    [InlineData("S-1-5-32-545")]
    [InlineData("S-1-1-0")]
    [InlineData(CustomDomainGroup)]
    [InlineData("not-a-sid")]
    public void Tampered_protection_json_sid_is_refused_on_load(string tampered)
    {
        var (resolved, refusals) = LoadPipeSid(storedSid: StandardUser, tamperedSid: tampered);

        Assert.Equal(ServiceAccount, resolved);
        Assert.Single(refusals);
    }

    [Theory]
    [InlineData(StandardUser)]
    [InlineData(EntraUser)]
    [InlineData(ServiceAccount)] // the service's own account adds no access
    public void Stored_user_sid_is_used_on_load(string stored)
    {
        var (resolved, refusals) = LoadPipeSid(stored, tamperedSid: null);

        Assert.Equal(stored, resolved);
        Assert.Empty(refusals);
    }

    [Fact]
    public void Group_sid_from_the_environment_override_is_refused()
    {
        var refusals = new List<string>();
        var store = new ProtectionSettingsStore(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()));

        var resolved = ServiceInfo.ResolveAllowedSid("S-1-1-0", store, ServiceAccount, FakeLookup, refusals.Add);

        Assert.Equal(ServiceAccount, resolved);
        Assert.Single(refusals);
    }

    [Fact]
    public void Real_account_lookup_classifies_sids_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // LookupAccountSid exists only on Windows; Windows CI runs this.
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();

        Assert.Equal(SidNameUse.User, AccountSid.Lookup(identity.User!.Value));
        Assert.Equal(SidNameUse.WellKnownGroup, AccountSid.Lookup("S-1-1-0"));
        Assert.Equal(SidNameUse.Alias, AccountSid.Lookup("S-1-5-32-545"));
        Assert.Null(AccountSid.Lookup("S-1-5-21-1-2-3-4000"));
        Assert.Null(AccountSid.Lookup("S-1-5-21-99999999999-2-3-4000"));
    }

    private static (string Resolved, List<string> Refusals) LoadPipeSid(string storedSid, string? tamperedSid)
    {
        var directory = Directory.CreateTempSubdirectory("axiom-allowed-sid-").FullName;
        try
        {
            var path = Path.Combine(directory, "protection.json");
            Assert.True(new ProtectionSettingsStore(path).Save(new ProtectionSettings { AllowedSid = storedSid }));
            if (tamperedSid is not null)
            {
                File.WriteAllText(path, File.ReadAllText(path).Replace(storedSid, tamperedSid, StringComparison.Ordinal));
            }

            var refusals = new List<string>();
            var resolved = ServiceInfo.ResolveAllowedSid(
                null, new ProtectionSettingsStore(path), ServiceAccount, FakeLookup, refusals.Add);
            return (resolved, refusals);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Fallback_to_the_elevated_identity_warns_when_it_differs_from_the_interactive_user()
    {
        var decision = ServiceInstaller.ResolveAllowedSid(null, ApprovingAdmin, StandardUser, FakeLookup);

        Assert.Equal(ApprovingAdmin, decision.Sid);
        Assert.Equal("elevated-fallback", decision.Source);
        Assert.NotNull(decision.Warning);
        Assert.Contains(StandardUser, decision.Warning, StringComparison.Ordinal);
        Assert.Contains("--allowed-sid", decision.Warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Fallback_is_quiet_when_the_elevated_identity_is_the_interactive_user()
    {
        var decision = ServiceInstaller.ResolveAllowedSid("  ", StandardUser, StandardUser, FakeLookup);

        Assert.Equal(StandardUser, decision.Sid);
        Assert.Equal("elevated-fallback", decision.Source);
        Assert.Null(decision.Warning);
    }
}
