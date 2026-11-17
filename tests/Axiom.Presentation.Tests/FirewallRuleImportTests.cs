// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Linq;
using Axiom.Contracts.Firewall;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class FirewallRuleImportTests
{
    [Fact]
    public void Exported_rules_round_trip_through_the_import_preview()
    {
        var rule = MakeRule(@"C:\Apps\agent.exe", FirewallAction.Block, "443");
        var json = FirewallRuleExport.ToJson([rule], DateTimeOffset.UnixEpoch);

        var result = FirewallRuleImport.Preview(json);

        Assert.True(result.SchemaValid);
        Assert.Null(result.FileError);
        var spec = Assert.Single(result.Rules);
        Assert.Equal(rule.ManagedRuleId, spec.ManagedRuleId);
        Assert.Equal(rule.Spec.AppPath, spec.AppPath);
        Assert.Equal(FirewallDirection.Outbound, spec.Direction);
        Assert.Equal(FirewallAction.Block, spec.Action);
        Assert.Empty(result.RuleErrors);
    }

    [Fact]
    public void Unsupported_schema_is_rejected_without_touching_rules()
    {
        var result = FirewallRuleImport.Preview("""{"schema":"other.v1","rules":[]}""");

        Assert.False(result.SchemaValid);
        Assert.Contains("Unsupported schema", result.FileError);
        Assert.Empty(result.Rules);
    }

    [Fact]
    public void Relative_application_path_is_reported_as_an_invalid_rule()
    {
        var rule = MakeRule(@"relative\agent.exe", FirewallAction.Block, "443");
        var json = FirewallRuleExport.ToJson([rule], DateTimeOffset.UnixEpoch);

        var result = FirewallRuleImport.Preview(json);

        Assert.True(result.SchemaValid);
        Assert.Empty(result.Rules);
        var error = Assert.Single(result.RuleErrors);
        Assert.Equal(0, error.Index);
        Assert.Contains("absolute", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Missing_managed_rule_id_is_reported()
    {
        const string json = """
            {
              "schema": "axiom.firewall-rules.v1",
              "rules": [
                { "appPath": "C:\\Apps\\agent.exe", "direction": "Outbound", "action": "Block" }
              ]
            }
            """;

        var result = FirewallRuleImport.Preview(json);

        Assert.True(result.SchemaValid);
        Assert.Single(result.RuleErrors);
        Assert.Contains("managedRuleId", result.RuleErrors[0].Message);
    }

    [Fact]
    public void Empty_or_missing_content_is_rejected()
    {
        Assert.False(FirewallRuleImport.Preview(null).SchemaValid);
        Assert.Contains("empty", FirewallRuleImport.Preview("   ").FileError, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("JSON", FirewallRuleImport.Preview("{").FileError);
    }

    private static ManagedRule MakeRule(string appPath, FirewallAction action, string ports)
    {
        var id = Guid.NewGuid();
        return new ManagedRule
        {
            ManagedRuleId = id,
            OsRuleName = "Axiom::preview::OUT",
            State = RuleState.Applied,
            Spec = new RuleSpec
            {
                ManagedRuleId = id,
                AppPath = appPath,
                Direction = FirewallDirection.Outbound,
                Action = action,
                Profiles = FirewallProfile.Private | FirewallProfile.Public,
                Protocol = NetworkProtocol.Tcp,
                RemotePorts = ports,
                RemoteAddresses = ["1.1.1.1"],
                Enabled = true,
                Description = "preview",
                CreatedBy = "AXIOM\\lab",
            },
        };
    }
}
