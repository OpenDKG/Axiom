// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;
using Axiom.Contracts.Ipc;

namespace Axiom.Core.Enforcement;

/// <summary>
/// Sends one bounded evaluation request to the local Axiom service. Implementations must return
/// <c>null</c> when the service is unavailable; the adapter then sends no deny and the host keeps its
/// current mode.
/// </summary>
public interface IEnforcementDecisionTransport
{
    Task<EnforcementVerdictDto?> EvaluateAsync(
        EnforcementEvaluateRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Same-user named-pipe transport. No HTTP, no remote endpoint, no generic execution.</summary>
public sealed class PipeEnforcementDecisionTransport(IpcPipeClient? client = null)
    : IEnforcementDecisionTransport
{
    private readonly IpcPipeClient _client = client ?? new IpcPipeClient();

    public async Task<EnforcementVerdictDto?> EvaluateAsync(
        EnforcementEvaluateRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            return await _client
                .SendAsync<EnforcementVerdictDto>(
                    IpcCommandTypes.EnforcementEvaluate,
                    request,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IpcClientException)
        {
            return null;
        }
    }
}

/// <summary>Combined result of evaluating a host action and emitting its redacted receipt.</summary>
public sealed record HostEnforcementOutcome(
    string? DenyPayload,
    EnforcementVerdictDto? Verdict,
    EnforcementReceiptV1 Receipt);

/// <summary>
/// Maps a real host pre-action event to the canonical request, asks the local service and returns a
/// host-specific deny payload only when the verdict is a block whose strength can actually carry it
/// out. An observation-strength block is advisory and produces no deny.
/// </summary>
public sealed class HostEnforcementAdapter(
    IEnforcementDecisionTransport transport,
    EnforcementReceiptJournal? journal = null)
{
    private readonly IEnforcementDecisionTransport _transport =
        transport ?? throw new ArgumentNullException(nameof(transport));

    private readonly EnforcementReceiptJournal? _journal = journal;

    public async Task<string?> BuildDenyAsync(
        HostHarness host,
        string agentId,
        string? sessionId,
        string? toolName,
        string? target,
        string? processPath,
        string requestId,
        bool hostSupportsDeny,
        BlackboxGuardSignal? guard,
        DateTimeOffset utcTime,
        CancellationToken cancellationToken)
    {
        var outcome = await EvaluateWithReceiptAsync(
            host,
            agentId,
            hostVersion: null,
            sessionId,
            toolName,
            target,
            processPath,
            requestId,
            hostSupportsDeny,
            guard,
            utcTime,
            cancellationToken).ConfigureAwait(false);

        return outcome.DenyPayload;
    }

    public async Task<HostEnforcementOutcome> EvaluateWithReceiptAsync(
        HostHarness host,
        string agentId,
        string? hostVersion,
        string? sessionId,
        string? toolName,
        string? target,
        string? processPath,
        string requestId,
        bool hostSupportsDeny,
        BlackboxGuardSignal? guard,
        DateTimeOffset utcTime,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        var kind = HostDecisionMapping.MapToolKind(toolName);
        var hostAdapterName = FormatHostName(host);
        var indicatorTarget = target ?? processPath;

        var request = new EnforcementEvaluateRequest
        {
            RequestId = requestId,
            AgentId = agentId,
            SessionId = sessionId,
            HostAdapter = hostAdapterName,
            HostVersion = hostVersion,
            Kind = kind.ToString(),
            Target = target,
            ProcessPath = processPath,
            UtcTime = utcTime,
            GuardAvailable = guard?.IsAvailable ?? false,
            GuardBlock = guard?.IsBlock ?? false,
            GuardSignalId = guard?.SignalId,
            CommunityOnly = guard?.CommunityOnly ?? false,
            HostSupportsDeny = hostSupportsDeny,
        };

        var verdict = await _transport.EvaluateAsync(request, cancellationToken).ConfigureAwait(false);
        if (verdict is null)
        {
            var failedOpen = EnforcementReceiptV1.Create(
                eventId: $"{requestId}:bridge",
                requestId: requestId,
                policyRevision: "0",
                hostAdapter: hostAdapterName,
                hostVersion: hostVersion,
                actionKind: kind,
                decisionSource: "pipe_unavailable",
                rawTargetOrIndicator: indicatorTarget,
                requestedDecision: EnforcementDecision.Unavailable,
                boundary: EnforcementBoundaryKind.None,
                result: EnforcementReceiptResult.FailedOpen,
                observedSideEffect: EnforcementObservedSideEffect.Unknown,
                verifiedBy: null,
                timestampUtc: utcTime);

            _journal?.TryAppend(failedOpen);
            return new HostEnforcementOutcome(null, null, failedOpen);
        }

        var parsedDecision = Enum.TryParse<EnforcementDecision>(verdict.Decision, ignoreCase: true, out var decision)
            ? decision
            : EnforcementDecision.Unavailable;

        var denyPayload = verdict.CanEnforce
            ? HostDecisionMapping.ToHostResponse(host, parsedDecision, "Blocked by Axiom policy.")
            : null;

        var (boundary, receiptResult) = ClassifyOutcome(verdict, parsedDecision, denyPayload);
        var receipt = EnforcementReceiptV1.Create(
            eventId: $"{requestId}:hook",
            requestId: requestId,
            policyRevision: verdict.PolicyRevision ?? "0",
            hostAdapter: hostAdapterName,
            hostVersion: hostVersion,
            actionKind: kind,
            decisionSource: verdict.RuleId,
            rawTargetOrIndicator: indicatorTarget,
            requestedDecision: parsedDecision,
            boundary: boundary,
            result: receiptResult,
            observedSideEffect: EnforcementObservedSideEffect.Unknown,
            verifiedBy: null,
            timestampUtc: verdict.EvaluatedUtc == default ? utcTime : verdict.EvaluatedUtc);

        _journal?.TryAppend(receipt);
        return new HostEnforcementOutcome(denyPayload, verdict, receipt);
    }

    /// <summary>
    /// Executes a disposable sentinel canary probe and returns a receipt whose
    /// <see cref="EnforcementReceiptResult.HostDenyVerified"/> status is awarded only when BOTH
    /// a host deny payload was produced AND the sentinel file state remained untouched.
    /// </summary>
    public async Task<HostEnforcementOutcome> VerifyDisposableCanaryAsync(
        HostHarness host,
        string agentId,
        string? hostVersion,
        string? toolName,
        string canaryFilePath,
        string requestId,
        BlackboxGuardSignal? guard,
        DateTimeOffset utcTime,
        Func<string?, CancellationToken, Task>? simulatedHostExecution,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canaryFilePath);

        var initialState = CaptureFileFingerprint(canaryFilePath);
        var outcome = await EvaluateWithReceiptAsync(
            host,
            agentId,
            hostVersion,
            sessionId: null,
            toolName,
            canaryFilePath,
            processPath: null,
            requestId,
            hostSupportsDeny: true,
            guard,
            utcTime,
            cancellationToken).ConfigureAwait(false);

        if (simulatedHostExecution is not null)
        {
            await simulatedHostExecution(outcome.DenyPayload, cancellationToken).ConfigureAwait(false);
        }

        if (outcome.DenyPayload is null)
        {
            return outcome;
        }

        var afterState = CaptureFileFingerprint(canaryFilePath);
        var sideEffectAbsent = string.Equals(initialState, afterState, StringComparison.Ordinal);

        var verifiedReceipt = EnforcementReceiptV1.Create(
            eventId: $"{requestId}:canary",
            requestId: requestId,
            policyRevision: outcome.Verdict?.PolicyRevision ?? "0",
            hostAdapter: FormatHostName(host),
            hostVersion: hostVersion,
            actionKind: HostDecisionMapping.MapToolKind(toolName),
            decisionSource: outcome.Verdict?.RuleId ?? "disposable-canary",
            rawTargetOrIndicator: canaryFilePath,
            requestedDecision: EnforcementDecision.Block,
            boundary: EnforcementBoundaryKind.HostHook,
            result: sideEffectAbsent
                ? EnforcementReceiptResult.HostDenyVerified
                : EnforcementReceiptResult.Unverified,
            observedSideEffect: sideEffectAbsent
                ? EnforcementObservedSideEffect.Absent
                : EnforcementObservedSideEffect.Present,
            verifiedBy: sideEffectAbsent ? "disposable-canary" : null,
            timestampUtc: outcome.Receipt.TimestampUtc);

        _journal?.TryAppend(verifiedReceipt);
        return new HostEnforcementOutcome(outcome.DenyPayload, outcome.Verdict, verifiedReceipt);
    }

    private static (EnforcementBoundaryKind Boundary, EnforcementReceiptResult Result) ClassifyOutcome(
        EnforcementVerdictDto verdict,
        EnforcementDecision decision,
        string? denyPayload)
    {
        if (decision == EnforcementDecision.Unavailable)
        {
            return (EnforcementBoundaryKind.None, EnforcementReceiptResult.GuardUnavailable);
        }

        if (decision == EnforcementDecision.Block)
        {
            return denyPayload is not null
                ? (EnforcementBoundaryKind.HostHook, EnforcementReceiptResult.HostDenySent)
                : (EnforcementBoundaryKind.DetectorOnly, EnforcementReceiptResult.DenyRequested);
        }

        if (decision == EnforcementDecision.Audit)
        {
            var boundary = verdict.AvailableStrength.Equals("hostHook", StringComparison.OrdinalIgnoreCase)
                ? EnforcementBoundaryKind.HostHook
                : EnforcementBoundaryKind.DetectorOnly;
            return (boundary, EnforcementReceiptResult.AuditOnly);
        }

        return (EnforcementBoundaryKind.HostHook, EnforcementReceiptResult.Detected);
    }

    private static string FormatHostName(HostHarness host) => host switch
    {
        HostHarness.OpenCode => "opencode",
        HostHarness.ClaudeCode => "claude",
        HostHarness.Codex => "codex",
        HostHarness.Cursor => "cursor",
        HostHarness.Copilot => "copilot",
        HostHarness.Gemini => "gemini",
        HostHarness.Windsurf => "windsurf",
        HostHarness.Cline => "cline",
        HostHarness.ZCode => "zcode",
        HostHarness.DeepSeek => "deepseek",
        _ => "unknown",
    };

    private static string CaptureFileFingerprint(string path)
    {
        if (!File.Exists(path))
        {
            return "absent";
        }

        var bytes = File.ReadAllBytes(path);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }
}
