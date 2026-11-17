// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class FirewallRuleExportTests
{
    [Fact]
    public void Export_carries_the_rule_intent_and_os_state()
    {
        var ruleId = Guid.NewGuid();
        var rule = new ManagedRule
        {
            ManagedRuleId = ruleId,
            OsRuleName = $"Axiom::{ruleId}::OUT",
            State = RuleState.Applied,
            LastVerifiedUtc = new DateTimeOffset(2026, 11, 17, 6, 0, 0, TimeSpan.Zero),
            OwnershipGroup = "Axiom",
            Spec = new RuleSpec
            {
                ManagedRuleId = ruleId,
                AppPath = @"C:\Apps\agent.exe",
                Direction = FirewallDirection.Outbound,
                Action = FirewallAction.Block,
                Profiles = FirewallProfile.Private | FirewallProfile.Public,
                Protocol = NetworkProtocol.Tcp,
                RemoteAddresses = ["1.1.1.1", "10.0.0.0/8"],
                RemotePorts = "443,8443",
                Enabled = true,
                Description = "test rule",
                CreatedBy = "AXIOM\\lab",
            },
        };

        var json = FirewallRuleExport.ToJson([rule], new DateTimeOffset(2026, 11, 17, 6, 30, 0, TimeSpan.Zero));

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(FirewallRuleExport.Schema, root.GetProperty("schema").GetString());
        Assert.Equal("2026-11-17T06:30:00.0000000+00:00", root.GetProperty("exportedAtUtc").GetString());

        var exported = Assert.Single(root.GetProperty("rules").EnumerateArray());
        Assert.Equal(ruleId, exported.GetProperty("managedRuleId").GetGuid());
        Assert.Equal(@"C:\Apps\agent.exe", exported.GetProperty("appPath").GetString());
        Assert.Equal("Outbound", exported.GetProperty("direction").GetString());
        Assert.Equal("Block", exported.GetProperty("action").GetString());
        Assert.Equal("Private, Public", exported.GetProperty("profiles").GetString());
        Assert.Equal("Tcp", exported.GetProperty("protocol").GetString());
        Assert.Equal("443,8443", exported.GetProperty("remotePorts").GetString());
        Assert.Equal(2, exported.GetProperty("remoteAddresses").GetArrayLength());
        Assert.Equal("AXIOM\\lab", exported.GetProperty("createdBy").GetString());
        Assert.Equal("Applied", exported.GetProperty("state").GetString());
    }

    [Fact]
    public void Empty_rule_list_exports_an_empty_array_with_the_schema()
    {
        var json = FirewallRuleExport.ToJson([], DateTimeOffset.UnixEpoch);

        using var document = JsonDocument.Parse(json);
        Assert.Equal(FirewallRuleExport.Schema, document.RootElement.GetProperty("schema").GetString());
        Assert.Equal(0, document.RootElement.GetProperty("rules").GetArrayLength());
    }
}
