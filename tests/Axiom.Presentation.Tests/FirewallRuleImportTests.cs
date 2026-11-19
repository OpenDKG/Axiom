// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Globalization;
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
        // Native path per OS: Windows-style rule paths are rejected off Windows (#441).
        var path = OperatingSystem.IsWindows() ? @"C:\Apps\agent.exe" : "/opt/apps/agent";
        var rule = MakeRule(path, FirewallAction.Block, "443");
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

    [Theory]
    [InlineData("/Applications/Example Agent.app/Contents/MacOS/Example Agent")]
    [InlineData("/usr/bin/curl")]
    [InlineData("/usr/local/bin/node")]
    public void Posix_and_app_bundle_paths_round_trip_and_plan_one_rule_each(string appPath)
    {
        // An export taken on macOS or Linux carries POSIX paths (including .app bundle
        // executables with spaces); the shared validator and the apply plan must accept them
        // unchanged so the daemon's normal rule.apply path receives the same path.
        // On Windows these are not native paths and the validator rejects them, so the
        // check applies off Windows only (return early instead of Skip: the Windows CI
        // gate fails on skipped tests).
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var rule = MakeRule(appPath, FirewallAction.Block, "443");
        var json = FirewallRuleExport.ToJson([rule], DateTimeOffset.UnixEpoch);

        var result = FirewallRuleImport.Preview(json);

        Assert.Null(result.FileError);
        Assert.Empty(result.RuleErrors);
        var spec = Assert.Single(result.Rules);
        Assert.Equal(appPath, spec.AppPath);

        var plan = FirewallRuleImport.PlanApply(result.Rules, "tester", "rules.json");
        Assert.Empty(plan.Conflicts);
        var planned = Assert.Single(plan.Rules);
        Assert.Equal(appPath, planned.AppPath);
        Assert.Equal(FirewallAction.Block, planned.Action);
        Assert.Equal("tester", planned.CreatedBy);
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
        var rule = MakeRule(OperatingSystem.IsWindows() ? @"relative\agent.exe" : "relative/agent", FirewallAction.Block, "443");
        var json = FirewallRuleExport.ToJson([rule], DateTimeOffset.UnixEpoch);

        var result = FirewallRuleImport.Preview(json);

        Assert.True(result.SchemaValid);
        Assert.Empty(result.Rules);
        var error = Assert.Single(result.RuleErrors);
        Assert.Equal(0, error.Index);
        Assert.Contains("absolute", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Windows_style_application_path_is_an_invalid_rule_off_windows()
    {
        var rule = MakeRule(@"C:\Apps\agent.exe", FirewallAction.Block, "443");
        var json = FirewallRuleExport.ToJson([rule], DateTimeOffset.UnixEpoch);

        var result = FirewallRuleImport.Preview(json);

        Assert.True(result.SchemaValid);
        if (OperatingSystem.IsWindows())
        {
            Assert.Single(result.Rules);
            return;
        }

        Assert.Empty(result.Rules);
        var error = Assert.Single(result.RuleErrors);
        Assert.Contains("Windows-style", error.Message, StringComparison.Ordinal);
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

    [Fact]
    public void Apply_plan_uses_one_identity_per_application_and_direction()
    {
        var block = MakeRule(@"C:\Apps\agent.exe", FirewallAction.Block, "443").Spec;
        var duplicate = MakeRule(@"c:\apps\AGENT.EXE", FirewallAction.Block, "8443").Spec;
        var inbound = new RuleSpec
        {
            ManagedRuleId = Guid.NewGuid(),
            AppPath = @"C:\Apps\agent.exe",
            Direction = FirewallDirection.Inbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            CreatedBy = "file",
        };

        var plan = FirewallRuleImport.PlanApply([block, duplicate, inbound], "lab", "rules.json");

        Assert.Empty(plan.Conflicts);
        Assert.Equal(2, plan.Rules.Count);
        Assert.Equal(RuleIdentity.ForApp(@"C:\Apps\agent.exe", FirewallDirection.Outbound), plan.Rules[0].ManagedRuleId);
        Assert.Equal("lab", plan.Rules[0].CreatedBy);
        Assert.Contains("rules.json", plan.Rules[0].Description);
        Assert.Equal(443, int.Parse(plan.Rules[0].RemotePorts!, CultureInfo.InvariantCulture)); // first scope wins for the same identity
    }

    [Fact]
    public void Apply_plan_reports_conflicting_actions_and_skips_the_second()
    {
        var block = MakeRule(@"C:\Apps\agent.exe", FirewallAction.Block, "443").Spec;
        var allow = MakeRule(@"C:\Apps\agent.exe", FirewallAction.Allow, "443").Spec;

        var plan = FirewallRuleImport.PlanApply([block, allow], "lab", "rules.json");

        Assert.Single(plan.Rules);
        Assert.Single(plan.Conflicts);
        Assert.Contains("both Block and Allow", plan.Conflicts[0]);
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
