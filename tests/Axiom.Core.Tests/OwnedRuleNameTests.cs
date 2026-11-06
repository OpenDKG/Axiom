// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class OwnedRuleNameTests
{
    private static readonly Guid RuleId = Guid.Parse("6f1a4d9e-8f42-4c1a-9b6e-1d2f3a4b5c6d");

    [Fact]
    public void Create_builds_the_documented_format()
    {
        var name = OwnedRuleName.Create(RuleId, FirewallDirection.Outbound);

        Assert.Equal($"Axiom::{RuleId:D}::OUT", name);
        Assert.StartsWith("Axiom::", name, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(FirewallDirection.Outbound, "OUT")]
    [InlineData(FirewallDirection.Inbound, "IN")]
    public void Create_then_parse_round_trips(FirewallDirection direction, string token)
    {
        var name = OwnedRuleName.Create(RuleId, direction);

        Assert.True(OwnedRuleName.TryParse(name, out var parsedId, out var parsedDirection));
        Assert.Equal(RuleId, parsedId);
        Assert.Equal(direction, parsedDirection);
        Assert.EndsWith($"::{token}", name, StringComparison.Ordinal);
    }

    [Fact]
    public void Legacy_rule_names_are_recognized_and_displayed_as_axiom()
    {
        var legacy = LegacyIdentity.RulePrefix + $"{RuleId:D}::OUT";

        Assert.True(OwnedRuleName.IsOwned(legacy));
        Assert.True(OwnedRuleName.TryParse(legacy, out var id, out var direction));
        Assert.Equal(RuleId, id);
        Assert.Equal(FirewallDirection.Outbound, direction);
        Assert.Equal($"Axiom::{RuleId:D}::OUT", OwnedRuleName.ToDisplayName(legacy));
    }

    [Fact]
    public void Create_rejects_an_empty_rule_id()
    {
        Assert.Throws<ArgumentException>(() => OwnedRuleName.Create(Guid.Empty, FirewallDirection.Outbound));
    }

    [Fact]
    public void Create_rejects_an_undefined_direction()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            OwnedRuleName.Create(RuleId, (FirewallDirection)42));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Axiom::not-a-guid::OUT")]
    [InlineData("Axiom::6f1a4d9e-8f42-4c1a-9b6e-1d2f3a4b5c6d::out")]
    [InlineData("Axiom::6f1a4d9e-8f42-4c1a-9b6e-1d2f3a4b5c6d::OUT::extra")]
    [InlineData("OtherProduct::6f1a4d9e-8f42-4c1a-9b6e-1d2f3a4b5c6d::OUT")]
    [InlineData("6f1a4d9e-8f42-4c1a-9b6e-1d2f3a4b5c6d::OUT")]
    public void TryParse_rejects_names_outside_the_contract(string? name)
    {
        Assert.False(OwnedRuleName.TryParse(name, out var id, out var direction));
        Assert.Equal(Guid.Empty, id);
    }

    [Theory]
    [InlineData("Axiom::garbage")]
    [InlineData("Axiom::")]
    public void IsOwned_is_conservative_for_malformed_names(string name)
    {
        Assert.True(OwnedRuleName.IsOwned(name));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("LocalFirewal::6f1a4d9e-8f42-4c1a-9b6e-1d2f3a4b5c6d::OUT")]
    public void IsOwned_ignores_foreign_names(string? name)
    {
        Assert.False(OwnedRuleName.IsOwned(name));
    }
}
