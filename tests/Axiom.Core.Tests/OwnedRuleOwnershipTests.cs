// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class OwnedRuleOwnershipTests
{
    private static readonly Guid Id = Guid.Parse("11111111-1111-1111-1111-111111111111");

    [Fact]
    public void Strict_name_and_group_prove_ownership()
    {
        Assert.True(OwnedRuleOwnership.IsRecoverable(NewRule()));
    }

    [Fact]
    public void Legacy_group_and_description_marker_are_still_owned()
    {
        Assert.True(OwnedRuleOwnership.HasOwnershipMetadata("Netpetra", null));
        Assert.True(OwnedRuleOwnership.HasOwnershipMetadata(null, "Axiom Shield block"));
        Assert.True(OwnedRuleOwnership.HasOwnershipMetadata("", "Netpetra shield"));
    }

    [Theory]
    [InlineData("OtherProduct", "unrelated rule")]
    [InlineData(null, null)]
    [InlineData("", "third-party")]
    public void Foreign_metadata_is_not_owned(string? group, string? description)
    {
        Assert.False(OwnedRuleOwnership.HasOwnershipMetadata(group, description));
    }

    [Fact]
    public void A_prefix_alone_is_not_enough_for_recovery()
    {
        var rule = NewRule() with
        {
            OsRuleName = "Axiom::not-a-guid::OUT",
        };

        Assert.False(OwnedRuleOwnership.IsRecoverable(rule));
    }

    [Fact]
    public void Name_identity_must_match_the_managed_rule()
    {
        var rule = NewRule() with
        {
            OsRuleName = OwnedRuleName.Create(
                Guid.Parse("22222222-2222-2222-2222-222222222222"),
                FirewallDirection.Outbound),
        };

        Assert.False(OwnedRuleOwnership.IsRecoverable(rule));
    }

    [Fact]
    public void Direction_must_match_the_specification()
    {
        var rule = NewRule() with
        {
            OsRuleName = OwnedRuleName.Create(Id, FirewallDirection.Inbound),
        };

        Assert.False(OwnedRuleOwnership.IsRecoverable(rule));
    }

    private static ManagedRule NewRule() => new()
    {
        ManagedRuleId = Id,
        OsRuleName = OwnedRuleName.Create(Id, FirewallDirection.Outbound),
        State = RuleState.Applied,
        Spec = new RuleSpec
        {
            ManagedRuleId = Id,
            AppPath = @"C:\test.exe",
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            CreatedBy = "test",
        },
        OwnershipGroup = "Axiom",
        OwnershipDescription = "Axiom managed rule",
    };
}
