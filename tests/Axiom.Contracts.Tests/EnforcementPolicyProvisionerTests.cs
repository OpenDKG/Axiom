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
    public void EnsureMachineDefault_covers_local_profiles_and_is_written_once()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-machine-{Guid.NewGuid():N}");
        try
        {
            var alice = Path.Combine(root, "alice");
            var bob = Path.Combine(root, "Bob");
            var publicProfile = Path.Combine(root, "Public");
            Directory.CreateDirectory(Path.Combine(alice, ".ssh"));
            Directory.CreateDirectory(Path.Combine(bob, "AppData", "Local", "Programs", "Axiom"));
            Directory.CreateDirectory(publicProfile);

            var policyPath = Path.Combine(root, "ProgramData", "Axiom", "enforcement-policy.json");
            var written = EnforcementPolicyProvisioner.EnsureMachineDefault(root, policyPath);
            Assert.NotNull(written);
            Assert.Equal(policyPath, written);

            var text = File.ReadAllText(written!);
            var policy = JsonNode.Parse(text)!["policy"]!.AsObject();
            var scopes = policy["protectedResources"]!.AsArray()
                .Select(resource => resource!["scope"]!.GetValue<string>())
                .ToArray();
            Assert.Contains(scopes, scope => scope.StartsWith(alice, StringComparison.OrdinalIgnoreCase));
            Assert.Contains(scopes, scope => scope.StartsWith(bob, StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(scopes, scope => scope.StartsWith(publicProfile, StringComparison.OrdinalIgnoreCase));

            var rules = policy["agents"]!.AsArray().Sum(agent => agent!["rules"]!.AsArray().Count);
            Assert.True(rules <= 512);
            Assert.Equal(scopes.Length * EnforcementPolicyProvisioner.AgentIds.Count, rules);

            Assert.Null(EnforcementPolicyProvisioner.EnsureMachineDefault(root, policyPath));
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

    [Fact]
    public void Defaults_write_nothing_off_windows()
    {
        // Off Windows the defaults would be /usr/share and the runner's real home; the provisioner
        // must refuse them. On Windows this would write ProgramData, so the check stops there.
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.Null(EnforcementPolicyProvisioner.EnsureDefault());
        Assert.Null(EnforcementPolicyProvisioner.EnsureDefault(userProfile: "/home/lab"));
        Assert.Null(EnforcementPolicyProvisioner.EnsureMachineDefault());
        Assert.False(File.Exists(EnforcementPolicyProvisioner.ResolvePath()));
    }
}
