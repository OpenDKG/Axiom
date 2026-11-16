// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json.Nodes;
using Axiom.Contracts.Enforcement;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class EnforcementPolicyProvisionerTests
{
    [Fact]
    public void Default_policy_is_an_enabled_block_policy_for_every_harness()
    {
        var json = EnforcementPolicyProvisioner.BuildDefaultPolicy(@"C:\Users\lab");
        var root = JsonNode.Parse(json)!.AsObject();

        Assert.True(root["enabled"]!.GetValue<bool>());
        var policy = root["policy"]!.AsObject();
        var agents = policy["agents"]!.AsArray();
        Assert.Equal(EnforcementPolicyProvisioner.AgentIds.Count, agents.Count);
        Assert.Equal(
            EnforcementPolicyProvisioner.AgentIds.Count * EnforcementPolicyProvisioner.ProtectedScopes.Count,
            agents.Sum(agent => agent!["rules"]!.AsArray().Count));

        var ruleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var agent in agents)
        {
            Assert.Equal("protectSelectedOperations", agent!["mode"]!.GetValue<string>());
            foreach (var rule in agent["rules"]!.AsArray())
            {
                Assert.True(ruleIds.Add(rule!["ruleId"]!.GetValue<string>()));
                Assert.Equal("block", rule["effect"]!.GetValue<string>());
                Assert.StartsWith(@"C:\Users\lab\", rule["targetScope"]!.GetValue<string>(), StringComparison.Ordinal);
            }
        }

        Assert.True(ruleIds.Count <= 512);
        var resources = policy["protectedResources"]!.AsArray();
        Assert.Equal(EnforcementPolicyProvisioner.ProtectedScopes.Count, resources.Count);
        Assert.Contains(
            resources,
            resource => resource!["scope"]!.GetValue<string>().EndsWith(@"\.ssh", StringComparison.Ordinal));
    }

    [Fact]
    public void EnsureDefault_writes_once_and_keeps_an_operator_policy()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-enforcement-{Guid.NewGuid():N}");
        try
        {
            var written = EnforcementPolicyProvisioner.EnsureDefault(root, @"C:\Users\lab");
            Assert.NotNull(written);
            Assert.True(File.Exists(written));
            Assert.Equal(
                written,
                EnforcementPolicyProvisioner.ResolvePath(root));
            Assert.Null(EnforcementPolicyProvisioner.EnsureDefault(root, @"C:\Users\lab"));

            File.WriteAllText(written!, "{\"enabled\":false,\"policy\":{\"agents\":[],\"protectedResources\":[]}}");
            Assert.Null(EnforcementPolicyProvisioner.EnsureDefault(root, @"C:\Users\lab"));
            Assert.Contains("\"enabled\":false", File.ReadAllText(written!), StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
