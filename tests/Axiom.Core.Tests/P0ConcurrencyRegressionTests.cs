// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class P0ConcurrencyRegressionTests
{
    [Fact]
    public async Task Evaluator_handles_concurrent_evaluations_and_evictions_without_collection_corruption()
    {
        var policy = new EnforcementPolicy
        {
            Agents =
            [
                new AgentEnforcementPolicy
                {
                    AgentId = "claude",
                    Mode = EnforcementMode.Monitor,
                    Rules =
                    [
                        new EnforcementRule
                        {
                            RuleId = "allow-work",
                            Effect = EnforcementRuleEffect.Allow,
                            TargetScope = @"C:\work",
                        },
                    ],
                },
            ],
        };

        var evaluator = new EnforcementPolicyEvaluator(policy);
        var now = new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

        var tasks = Enumerable.Range(0, 64).Select(worker => Task.Run(() =>
        {
            for (var i = 0; i < 60; i++)
            {
                var reqId = i % 3 == 0 ? $"shared-{i % 10}" : $"w{worker}-{i}";
                var req = new AgentActionRequest
                {
                    RequestId = reqId,
                    AgentId = "claude",
                    Kind = AgentActionKind.ReadFile,
                    Target = @"C:\work\file.txt",
                    UtcTime = now,
                };
                var verdict = evaluator.Evaluate(req);
                Assert.Equal(EnforcementDecision.Allow, verdict.Decision);
            }
        }));

        await Task.WhenAll(tasks);
    }
}
