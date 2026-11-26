// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Infrastructure.Linux.Monitoring;
using Axiom.Infrastructure.Linux.ProcessIdentity;
using Axiom.Infrastructure.Unix.Filter;
using Axiom.Infrastructure.Unix.Monitoring;

namespace Axiom.Service.Unix.Tests;

public sealed class LinuxBlockedFlowTests
{
    [Theory]
    [InlineData("4cc3afda-8297-4606-8b15-716f274a62aa", ConnectionRuleStatus.BlockedByOwnedRule)]
    [InlineData(null, ConnectionRuleStatus.BlockedByExternalPolicy)]
    public void FilterBlockSurvivesRuleEvaluationWithAnEmptyCache(string? ruleId, ConnectionRuleStatus expected)
    {
        var flows = new FlowTable();
        var source = new LinuxConnectionSource(
            () => [], new ProcProcessIdentityResolver(), TimeProvider.System, privileged: false, flows);
        flows.Apply(new FlowEvent
        {
            Type = FlowEventType.Open,
            Id = "bpf-1",
            Path = "/usr/bin/curl",
            Direction = "outbound",
            Protocol = "udp",
            LocalAddress = "0.0.0.0",
            RemoteAddress = "192.0.2.1",
            RemotePort = 443,
            Verdict = "block",
            RuleId = ruleId,
        }, DateTimeOffset.UtcNow);

        var connection = Assert.Single(source.Capture(CancellationToken.None).Connections);
        Assert.Equal(expected, OwnedRuleMatcher.Evaluate([], connection));
        Assert.Empty(source.Capture(CancellationToken.None).Connections);
    }
}
