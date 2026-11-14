// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class HostEnforcementAdapterTests
{
    private static readonly DateTimeOffset Observed =
        new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Unavailable_transport_sends_no_deny_and_records_failed_open_receipt()
    {
        var journal = new EnforcementReceiptJournal();
        var adapter = new HostEnforcementAdapter(new FakeTransport(null), journal);

        var outcome = await adapter.EvaluateWithReceiptAsync(
            HostHarness.Codex, "opencode", "1.0", "s-1", "shell", @"C:\lab\x", null, "req-1",
            hostSupportsDeny: true, guard: null, Observed, CancellationToken.None);

        Assert.Null(outcome.DenyPayload);
        Assert.Equal(EnforcementReceiptResult.FailedOpen, outcome.Receipt.Result);
        Assert.Equal("FAILED_OPEN", outcome.Receipt.ResultToken);
        Assert.Equal(1, journal.Count);
    }

    [Fact]
    public async Task Observation_strength_block_sends_no_deny_and_records_deny_requested()
    {
        var journal = new EnforcementReceiptJournal();
        var adapter = new HostEnforcementAdapter(new FakeTransport(Verdict("block", canEnforce: false)), journal);

        var outcome = await adapter.EvaluateWithReceiptAsync(
            HostHarness.Codex, "opencode", "1.0", "s-1", "shell", @"C:\lab\x", null, "req-1",
            hostSupportsDeny: false, guard: null, Observed, CancellationToken.None);

        Assert.Null(outcome.DenyPayload);
        Assert.Equal(EnforcementReceiptResult.DenyRequested, outcome.Receipt.Result);
        Assert.Equal(EnforcementBoundaryKind.DetectorOnly, outcome.Receipt.Boundary);
    }

    [Fact]
    public async Task Allow_sends_no_deny()
    {
        var adapter = new HostEnforcementAdapter(new FakeTransport(Verdict("allow", canEnforce: true)));

        var deny = await adapter.BuildDenyAsync(
            HostHarness.Codex, "opencode", "s-1", "read", @"C:\lab\x", null, "req-1",
            hostSupportsDeny: true, guard: null, Observed, CancellationToken.None);

        Assert.Null(deny);
    }

    [Fact]
    public async Task Enforceable_codex_block_returns_the_codex_payload_and_records_host_deny_sent()
    {
        var journal = new EnforcementReceiptJournal();
        var adapter = new HostEnforcementAdapter(new FakeTransport(Verdict("block", canEnforce: true)), journal);

        var outcome = await adapter.EvaluateWithReceiptAsync(
            HostHarness.Codex, "codex", "0.9", "s-1", "shell", @"C:\lab\x", null, "req-1",
            hostSupportsDeny: true, guard: null, Observed, CancellationToken.None);

        Assert.NotNull(outcome.DenyPayload);
        using var document = JsonDocument.Parse(outcome.DenyPayload);
        Assert.Equal("block", document.RootElement.GetProperty("decision").GetString());
        Assert.Equal(EnforcementReceiptResult.HostDenySent, outcome.Receipt.Result);
        Assert.Equal(EnforcementObservedSideEffect.Unknown, outcome.Receipt.ObservedSideEffect);
    }

    [Fact]
    public async Task Enforceable_claude_block_returns_the_pre_tool_use_payload()
    {
        var adapter = new HostEnforcementAdapter(new FakeTransport(Verdict("block", canEnforce: true)));

        var deny = await adapter.BuildDenyAsync(
            HostHarness.ClaudeCode, "claude", "s-1", "Bash", @"C:\lab\x", null, "req-1",
            hostSupportsDeny: true, guard: null, Observed, CancellationToken.None);

        Assert.NotNull(deny);
        using var document = JsonDocument.Parse(deny);
        var hook = document.RootElement.GetProperty("hookSpecificOutput");
        Assert.Equal("PreToolUse", hook.GetProperty("hookEventName").GetString());
        Assert.Equal("deny", hook.GetProperty("permissionDecision").GetString());
    }

    [Fact]
    public async Task Request_carries_mapped_kind_target_and_guard_signal()
    {
        var transport = new FakeTransport(Verdict("allow", canEnforce: false));
        var adapter = new HostEnforcementAdapter(transport);
        var guard = new BlackboxGuardSignal
        {
            IsAvailable = true,
            IsBlock = true,
            SignalId = "g-1",
            CommunityOnly = true,
        };

        _ = await adapter.BuildDenyAsync(
            HostHarness.OpenCode, "opencode", "session-7", "shell", @"C:\lab\tool", @"C:\bin\sh.exe",
            "req-9", hostSupportsDeny: true, guard, Observed, CancellationToken.None);

        var request = Assert.IsType<EnforcementEvaluateRequest>(transport.LastRequest);
        Assert.Equal("opencode", request.AgentId);
        Assert.Equal("session-7", request.SessionId);
        Assert.Equal("ExecuteProcess", request.Kind);
        Assert.Equal(@"C:\lab\tool", request.Target);
        Assert.Equal(@"C:\bin\sh.exe", request.ProcessPath);
        Assert.True(request.HostSupportsDeny);
        Assert.True(request.GuardAvailable);
        Assert.True(request.GuardBlock);
        Assert.True(request.CommunityOnly);
        Assert.Equal("g-1", request.GuardSignalId);
        Assert.Equal(Observed, request.UtcTime);
    }

    [Fact]
    public async Task Disposable_canary_records_host_deny_verified_only_when_sentinel_untouched()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"axiom-canary-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var canaryPath = Path.Combine(tempDir, "secret-canary.txt");

        try
        {
            var journal = new EnforcementReceiptJournal();
            var adapter = new HostEnforcementAdapter(new FakeTransport(Verdict("block", canEnforce: true)), journal);

            var verifiedOutcome = await adapter.VerifyDisposableCanaryAsync(
                HostHarness.ClaudeCode,
                "claude",
                "1.2.3",
                "write_file",
                canaryPath,
                "req-canary-ok",
                guard: null,
                Observed,
                (denyPayload, _) =>
                {
                    if (denyPayload is null)
                    {
                        File.WriteAllText(canaryPath, "BREACH");
                    }

                    return Task.CompletedTask;
                },
                CancellationToken.None);

            Assert.False(File.Exists(canaryPath));
            Assert.Equal(EnforcementReceiptResult.HostDenyVerified, verifiedOutcome.Receipt.Result);
            Assert.Equal(EnforcementObservedSideEffect.Absent, verifiedOutcome.Receipt.ObservedSideEffect);
            Assert.Equal("disposable-canary", verifiedOutcome.Receipt.VerifiedBy);

            var bypassedOutcome = await adapter.VerifyDisposableCanaryAsync(
                HostHarness.ClaudeCode,
                "claude",
                "1.2.3",
                "write_file",
                canaryPath,
                "req-canary-bypass",
                guard: null,
                Observed,
                (_, _) =>
                {
                    File.WriteAllText(canaryPath, "BYPASSED");
                    return Task.CompletedTask;
                },
                CancellationToken.None);

            Assert.Equal(EnforcementReceiptResult.Unverified, bypassedOutcome.Receipt.Result);
            Assert.Equal(EnforcementObservedSideEffect.Present, bypassedOutcome.Receipt.ObservedSideEffect);
            Assert.Null(bypassedOutcome.Receipt.VerifiedBy);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    private static EnforcementVerdictDto Verdict(string decision, bool canEnforce) => new()
    {
        RequestId = "req-1",
        Decision = decision,
        RuleId = "rule-1",
        ReasonCode = decision == "block" ? EnforcementReasonCodes.RuleBlock : EnforcementReasonCodes.RuleAllow,
        AvailableStrength = canEnforce ? "hostHook" : "observation",
        CanEnforce = canEnforce,
        EvaluatedUtc = Observed,
        PolicyRevision = "1",
    };

    private sealed class FakeTransport(EnforcementVerdictDto? verdict) : IEnforcementDecisionTransport
    {
        public EnforcementEvaluateRequest? LastRequest { get; private set; }

        public Task<EnforcementVerdictDto?> EvaluateAsync(
            EnforcementEvaluateRequest request,
            CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(verdict);
        }
    }
}
