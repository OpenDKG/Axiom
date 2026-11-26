// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class AgentNetworkAndBrokerTests
{
    private static readonly DateTimeOffset Observed =
        new(2026, 11, 14, 6, 30, 0, TimeSpan.Zero);

    [Fact]
    public void Scoped_rule_identity_is_deterministic_and_distinct_per_endpoint()
    {
        var a1 = RuleIdentity.ForAgentEndpoint(@"C:\Agents\opencode.exe", FirewallDirection.Outbound, "198.51.100.10", "443");
        var a2 = RuleIdentity.ForAgentEndpoint(" c:/agents/opencode.exe ", FirewallDirection.Outbound, "198.51.100.10", "443");
        var b = RuleIdentity.ForAgentEndpoint(@"C:\Agents\opencode.exe", FirewallDirection.Outbound, "203.0.113.20", "443");
        var appWide = RuleIdentity.ForApp(@"C:\Agents\opencode.exe", FirewallDirection.Outbound);

        Assert.Equal(a1, a2);
        Assert.NotEqual(a1, b);
        Assert.NotEqual(a1, appWide);
    }

    [Theory]
    [InlineData(AgentNetworkPolicyOrigin.CommunitySignal)]
    [InlineData(AgentNetworkPolicyOrigin.PublicFeed)]
    public void Planner_refuses_community_and_public_feed_signals_without_explicit_authorization(
        AgentNetworkPolicyOrigin origin)
    {
        var plan = AgentFirewallRulePlanner.BuildScopedBlockSpec(new AgentFirewallRuleIntent
        {
            ExecutablePath = @"C:\Agents\codex.exe",
            RemoteAddressOrCidr = "198.51.100.5",
            RemotePorts = "443",
            Origin = origin,
            ExplicitlyAuthorizedByUser = false,
            ActorSid = "S-1-5-21-1",
        });

        Assert.False(plan.IsAllowedToWriteOsRule);
        Assert.Null(plan.Spec);
        Assert.Equal(EnforcementReasonCodes.CommunityAdvisoryOnly, plan.RejectionReasonCode);
    }

    [Fact]
    public void Planner_builds_valid_scoped_rule_for_authorized_local_policy()
    {
        // Native path per OS: Windows-style rule paths are rejected off Windows (#441).
        var agent = OperatingSystem.IsWindows() ? @"C:\Agents\claude.exe" : "/opt/agents/claude";
        var plan = AgentFirewallRulePlanner.BuildScopedBlockSpec(new AgentFirewallRuleIntent
        {
            ExecutablePath = agent,
            RemoteAddressOrCidr = "203.0.113.0/24",
            RemotePorts = "8443",
            Origin = AgentNetworkPolicyOrigin.LocalUserPolicy,
            ExplicitlyAuthorizedByUser = true,
            ActorSid = "S-1-5-21-1",
        });

        Assert.True(plan.IsAllowedToWriteOsRule);
        var spec = Assert.IsType<RuleSpec>(plan.Spec);
        Assert.Equal(FirewallDirection.Outbound, spec.Direction);
        Assert.Equal(FirewallAction.Block, spec.Action);
        Assert.Equal(["203.0.113.0/24"], spec.RemoteAddresses);
        Assert.Equal("8443", spec.RemotePorts);
    }

    [Theory]
    [InlineData(@"\\?\C:\secret.txt")]
    [InlineData(@"\\server\share\secret.txt")]
    [InlineData(@"relative\secret.txt")]
    public void Trusted_file_broker_rejects_unsafe_or_relative_paths(string path)
    {
        var evaluator = new EnforcementPolicyEvaluator(new EnforcementPolicy
        {
            Version = "1",
            Agents =
            [
                new AgentEnforcementPolicy
                {
                    AgentId = "opencode",
                    Mode = EnforcementMode.ProtectSelectedOperations,
                    Rules = [],
                },
            ],
        });
        var journal = new EnforcementReceiptJournal();
        var broker = new TrustedFileBroker(evaluator, _ => false, journal, "rev-1");

        var result = broker.OpenRead("opencode", "req-unsafe", path, Observed);

        Assert.Equal(BrokerAccessDecision.DeniedUnsafePath, result.Decision);
        Assert.Null(result.ContentBytes);
        Assert.Equal(EnforcementReceiptResult.OsDenyVerified, result.Receipt.Result);
        Assert.Equal(EnforcementObservedSideEffect.Absent, result.Receipt.ObservedSideEffect);
    }

    [Fact]
    public void Trusted_file_broker_rejects_reparse_points_and_protected_resources_and_allows_explicit_allow()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"axiom-broker-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var allowedFile = Path.Combine(tempDir, "allowed.txt");
        var secretFile = Path.Combine(tempDir, "secret.env");
        File.WriteAllText(allowedFile, "hello-broker");
        File.WriteAllText(secretFile, "SECRET=1");

        try
        {
            // The broker decides on the path it resolves from the open handle (for example the long
            // form of an 8.3 temp path on Windows), so policy scopes use that same form.
            Assert.True(TrustedFileBroker.TryResolveFinalPath(secretFile, out var secretFinal));
            Assert.True(TrustedFileBroker.TryResolveFinalPath(allowedFile, out var allowedFinal));
            var workDir = Path.GetDirectoryName(allowedFinal)!;
            var policy = new EnforcementPolicy
            {
                Version = "1",
                ProtectedResources =
                [
                    new ProtectedResource
                    {
                        ResourceId = "res-env",
                        Kinds = [AgentActionKind.ReadFile],
                        Scope = secretFinal,
                    },
                ],
                Agents =
                [
                    new AgentEnforcementPolicy
                    {
                        AgentId = "opencode",
                        Mode = EnforcementMode.ProtectSelectedOperations,
                        Rules =
                        [
                            new EnforcementRule
                            {
                                RuleId = "allow-work",
                                Effect = EnforcementRuleEffect.Allow,
                                Kind = AgentActionKind.ReadFile,
                                TargetScope = workDir,
                            },
                        ],
                    },
                ],
            };
            var evaluator = new EnforcementPolicyEvaluator(policy);
            var journal = new EnforcementReceiptJournal();

            var symlinkBroker = new TrustedFileBroker(
                evaluator,
                path => string.Equals(path, allowedFile, StringComparison.OrdinalIgnoreCase),
                journal,
                "rev-1");
            var reparseDenied = symlinkBroker.OpenRead("opencode", "req-sym", allowedFile, Observed);
            Assert.Equal(BrokerAccessDecision.DeniedReparseOrSymlink, reparseDenied.Decision);
            Assert.Null(reparseDenied.ContentBytes);

            var cleanBroker = new TrustedFileBroker(evaluator, _ => false, journal, "rev-1");
            var secretDenied = cleanBroker.OpenRead("opencode", "req-secret", secretFile, Observed);
            Assert.Equal(BrokerAccessDecision.DeniedByPolicy, secretDenied.Decision);
            Assert.Null(secretDenied.ContentBytes);

            var allowed = cleanBroker.OpenRead("opencode", "req-ok", allowedFile, Observed);
            Assert.Equal(BrokerAccessDecision.Allowed, allowed.Decision);
            Assert.Equal("hello-broker", System.Text.Encoding.UTF8.GetString(allowed.ContentBytes!));
            Assert.True(journal.VerifyChain());
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
