// SPDX-License-Identifier: GPL-3.0-or-later
using Netrigil.Contracts.Firewall;
using Netrigil.Core.Firewall;
using Xunit;

namespace Netrigil.Core.Tests;

public sealed class RuleIdentityTests
{
    private const string Path = @"C:\Program Files\Example\example.exe";

    [Fact]
    public void Same_path_and_direction_produce_the_same_id()
    {
        var first = RuleIdentity.ForApp(Path, FirewallDirection.Outbound);
        var second = RuleIdentity.ForApp(Path, FirewallDirection.Outbound);

        Assert.Equal(first, second);
        Assert.NotEqual(Guid.Empty, first);
    }

    [Theory]
    [InlineData(@"C:\PROGRAM FILES\EXAMPLE\EXAMPLE.EXE")]
    [InlineData(@"C:/Program Files/Example/example.exe")]
    [InlineData(@"  C:\Program Files\Example\example.exe  ")]
    public void Path_normalisation_is_case_and_separator_insensitive(string equivalent)
    {
        var original = RuleIdentity.ForApp(Path, FirewallDirection.Outbound);
        var other = RuleIdentity.ForApp(equivalent, FirewallDirection.Outbound);

        Assert.Equal(original, other);
    }

    [Fact]
    public void Inbound_and_outbound_ids_differ()
    {
        var outbound = RuleIdentity.ForApp(Path, FirewallDirection.Outbound);
        var inbound = RuleIdentity.ForApp(Path, FirewallDirection.Inbound);

        Assert.NotEqual(outbound, inbound);
    }

    [Fact]
    public void Different_paths_produce_different_ids()
    {
        var first = RuleIdentity.ForApp(Path, FirewallDirection.Outbound);
        var second = RuleIdentity.ForApp(@"C:\Tools\other.exe", FirewallDirection.Outbound);

        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_path_is_rejected(string path)
    {
        Assert.Throws<ArgumentException>(() => RuleIdentity.ForApp(path, FirewallDirection.Outbound));
    }
}
