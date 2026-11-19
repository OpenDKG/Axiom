// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Service.Tests;

public sealed class EnforcementControllerTests
{
    private static readonly DateTimeOffset Observed =
        new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    private const string EnabledPolicy = """
        {
          "enabled": true,
          "policy": {
            "version": "test-1",
            "agents": [
              {
                "agentId": "opencode",
                "mode": "monitor",
                "rules": [
                  { "ruleId": "allow-read", "effect": "allow", "kind": "readFile", "targetScope": "C:\\lab\\allowed" },
                  { "ruleId": "block-read", "effect": "block", "kind": "readFile", "targetScope": "C:\\lab\\secret" }
                ]
              }
            ],
            "protectedResources": []
          }
        }
        """;

    [Fact]
    public void Default_provisioning_is_windows_only()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var policy = new TemporaryPolicy(null);
        var controller = new EnforcementController(policy.PolicyPath, provisionDefaultIfMissing: true);

        Assert.False(controller.GetStatus().Enabled);
        Assert.False(File.Exists(policy.PolicyPath));
    }

    [Fact]
    public async Task Missing_policy_file_is_disabled_and_returns_unavailable()
    {
        using var policy = new TemporaryPolicy(null);
        var controller = new EnforcementController(policy.PolicyPath);

        Assert.False(controller.GetStatus().Enabled);

        var verdict = await controller.EvaluateAsync(
            Request("req-1", "readFile", @"C:\lab\allowed"), "S-1-5-21-1", CancellationToken.None);

        Assert.Equal("unavailable", verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.Disabled, verdict.ReasonCode);
        Assert.False(verdict.CanEnforce);
        Assert.Equal("GUARD_UNAVAILABLE", verdict.ReceiptResult);
    }

    [Fact]
    public async Task Missing_caller_identity_is_rejected()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        var verdict = await controller.EvaluateAsync(
            Request("req-1", "readFile", @"C:\lab\allowed"), " ", CancellationToken.None);

        Assert.Equal("unavailable", verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.Unauthenticated, verdict.ReasonCode);
        Assert.Equal("GUARD_UNAVAILABLE", verdict.ReceiptResult);
    }

    [Fact]
    public async Task Allow_rule_is_evaluated_with_host_strength()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        var verdict = await controller.EvaluateAsync(
            Request("req-2", "readFile", @"C:\lab\allowed", hostSupportsDeny: true),
            "S-1-5-21-1",
            CancellationToken.None);

        Assert.Equal("allow", verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.RuleAllow, verdict.ReasonCode);
        Assert.Equal("hostHook", verdict.AvailableStrength);
        Assert.True(verdict.CanEnforce);
        Assert.Equal("test-1", verdict.PolicyRevision);
        Assert.Equal("DETECTED", verdict.ReceiptResult);
    }

    [Fact]
    public async Task Block_without_host_deny_is_observation_not_verified()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        var verdict = await controller.EvaluateAsync(
            Request("req-3", "readFile", @"C:\lab\secret", hostSupportsDeny: false),
            "S-1-5-21-1",
            CancellationToken.None);

        Assert.Equal("block", verdict.Decision);
        Assert.Equal(EnforcementReasonCodes.RuleBlock, verdict.ReasonCode);
        Assert.Equal("observation", verdict.AvailableStrength);
        Assert.False(verdict.CanEnforce);
        Assert.Equal("DENY_REQUESTED", verdict.ReceiptResult);
    }

    [Fact]
    public async Task Block_with_host_deny_records_host_deny_sent_never_verified_from_evaluate()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        var verdict = await controller.EvaluateAsync(
            Request("req-3b", "readFile", @"C:\lab\secret", hostSupportsDeny: true),
            "S-1-5-21-1",
            CancellationToken.None);

        Assert.Equal("block", verdict.Decision);
        Assert.True(verdict.CanEnforce);
        Assert.Equal("HOST_DENY_SENT", verdict.ReceiptResult);

        var receipts = controller.GetReceipts();
        Assert.True(receipts.ChainValid);
        Assert.Equal(1, receipts.Total);
        Assert.Equal("HOST_DENY_SENT", receipts.Receipts[0].Result);
        Assert.Equal("unknown", receipts.Receipts[0].ObservedSideEffect);
        Assert.DoesNotContain(@"C:\lab\secret", receipts.Receipts[0].IndicatorRef, StringComparison.OrdinalIgnoreCase);

        var status = controller.GetStatus();
        Assert.Equal(1, status.HostDenySentCount);
        Assert.Equal(0, status.HostDenyVerifiedCount);
    }

    [Fact]
    public async Task Guard_block_overrides_an_allow_rule_unless_community_only()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        var localGuardVerdict = await controller.EvaluateAsync(
            Request("req-4", "readFile", @"C:\lab\allowed", hostSupportsDeny: true, guardBlock: true, communityOnly: false),
            "S-1-5-21-1",
            CancellationToken.None);

        Assert.Equal("block", localGuardVerdict.Decision);
        Assert.Equal(EnforcementReasonCodes.GuardBlock, localGuardVerdict.ReasonCode);

        var communityVerdict = await controller.EvaluateAsync(
            Request("req-4b", "readFile", @"C:\lab\unmatched", hostSupportsDeny: true, guardBlock: true, communityOnly: true),
            "S-1-5-21-1",
            CancellationToken.None);

        Assert.Equal("audit", communityVerdict.Decision);
        Assert.Equal(EnforcementReasonCodes.CommunityAdvisoryOnly, communityVerdict.ReasonCode);
        Assert.Equal("AUDIT_ONLY", communityVerdict.ReceiptResult);
    }

    [Fact]
    public async Task Invalid_kind_and_oversized_target_are_rejected()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        var invalidKind = await controller.EvaluateAsync(
            Request("req-5", "notARealKind", @"C:\lab\allowed"), "S-1-5-21-1", CancellationToken.None);
        var oversized = await controller.EvaluateAsync(
            Request("req-6", "readFile", @"C:\lab\" + new string('x', 4096)),
            "S-1-5-21-1",
            CancellationToken.None);

        Assert.Equal(EnforcementReasonCodes.InvalidRequest, invalidKind.ReasonCode);
        Assert.Equal(EnforcementReasonCodes.InvalidRequest, oversized.ReasonCode);
    }

    [Fact]
    public async Task Reusing_a_request_id_for_a_different_action_is_rejected()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        _ = await controller.EvaluateAsync(
            Request("req-7", "readFile", @"C:\lab\secret"), "S-1-5-21-1", CancellationToken.None);

        var second = await controller.EvaluateAsync(
            Request("req-7", "readFile", @"C:\lab\allowed"), "S-1-5-21-1", CancellationToken.None);

        Assert.Equal("unavailable", second.Decision);
        Assert.Equal(EnforcementReasonCodes.ReplayMismatch, second.ReasonCode);
    }

    [Fact]
    public async Task Repeated_identical_request_returns_the_same_verdict()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);
        var request = Request("req-8", "readFile", @"C:\lab\allowed", hostSupportsDeny: true);

        var first = await controller.EvaluateAsync(request, "S-1-5-21-1", CancellationToken.None);
        var second = await controller.EvaluateAsync(request, "S-1-5-21-1", CancellationToken.None);

        Assert.Equal(first.Decision, second.Decision);
        Assert.Equal(first.RuleId, second.RuleId);
        Assert.Equal(first.EvaluatedUtc, second.EvaluatedUtc);
    }

    [Fact]
    public void Status_reports_revision_and_rule_counts()
    {
        using var policy = new TemporaryPolicy(EnabledPolicy);
        var controller = new EnforcementController(policy.PolicyPath);

        var status = controller.GetStatus();

        Assert.True(status.Enabled);
        Assert.Equal("test-1", status.Revision);
        Assert.Equal(1, status.AgentCount);
        Assert.Equal(2, status.RuleCount);
        Assert.Null(status.Error);
    }

    [Fact]
    public void Malformed_policy_is_reported_not_silently_enabled()
    {
        using var policy = new TemporaryPolicy("{ not json");
        var controller = new EnforcementController(policy.PolicyPath);

        var status = controller.GetStatus();

        Assert.False(status.Enabled);
        Assert.False(string.IsNullOrWhiteSpace(status.Error));
    }

    [Fact]
    public void Disabled_policy_file_keeps_enforcement_off()
    {
        using var policy = new TemporaryPolicy("""{ "enabled": false }""");
        var controller = new EnforcementController(policy.PolicyPath);

        Assert.False(controller.GetStatus().Enabled);
    }

    private static EnforcementEvaluateRequest Request(
        string requestId,
        string kind,
        string? target,
        bool hostSupportsDeny = false,
        bool guardBlock = false,
        bool communityOnly = false) => new()
        {
            RequestId = requestId,
            AgentId = "opencode",
            SessionId = "session-1",
            Kind = kind,
            Target = target,
            UtcTime = Observed,
            HostSupportsDeny = hostSupportsDeny,
            GuardAvailable = guardBlock,
            GuardBlock = guardBlock,
            GuardSignalId = guardBlock ? "guard-1" : null,
            CommunityOnly = communityOnly,
        };

    private sealed class TemporaryPolicy : IDisposable
    {
        private readonly string? _directory;

        public TemporaryPolicy(string? json)
        {
            _directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"axiom-enf-{Guid.NewGuid():N}");
            Directory.CreateDirectory(_directory);
            PolicyPath = System.IO.Path.Combine(_directory, "enforcement-policy.json");
            if (json is not null)
            {
                File.WriteAllText(PolicyPath, json);
            }
        }

        public string PolicyPath { get; }

        public void Dispose()
        {
            try
            {
                if (_directory is not null && Directory.Exists(_directory))
                {
                    Directory.Delete(_directory, recursive: true);
                }
            }
            catch
            {
            }
        }
    }
}
