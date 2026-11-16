// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Enforcement;
using Axiom.Contracts.Ipc;
using Axiom.Core.Enforcement;

namespace Axiom.Service;

/// <summary>
/// Offline enforcement decision boundary. It loads a user-owned policy file, evaluates a bounded
/// request with the existing deterministic <see cref="EnforcementPolicyEvaluator"/>, records a
/// redacted <see cref="EnforcementReceiptV1"/> entry, and returns an honest verdict. It is off
/// unless a valid policy file enables it, and it never writes user files, contacts the network, or
/// turns a decision into a claim that a host obeyed it.
/// </summary>
public sealed class EnforcementController
{
    private const int MaximumIdentityLength = 128;
    private const int MaximumTargetLength = 4096;
    private const int MaximumRememberedRequests = 1024;

    private readonly string _policyPath;
    private readonly bool _provisionDefaultIfMissing;
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _fingerprints = new(StringComparer.Ordinal);
    private readonly Queue<string> _fingerprintOrder = new();
    private readonly EnforcementReceiptJournal _journal = new();

    private CachedPolicy? _cached;

    public EnforcementController()
        : this(DefaultPolicyPath(), provisionDefaultIfMissing: true)
    {
    }

    public EnforcementController(string policyPath, bool provisionDefaultIfMissing = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyPath);
        _policyPath = Path.GetFullPath(policyPath);
        _provisionDefaultIfMissing = provisionDefaultIfMissing;
    }

    public string PolicyPath => _policyPath;

    /// <summary>Shared receipt journal for correlated host and OS boundary receipts.</summary>
    public EnforcementReceiptJournal ReceiptJournal => _journal;

    /// <summary>Current policy state and receipt summary. Missing file means disabled, not an error.</summary>
    public EnforcementStatusDto GetStatus()
    {
        if (_provisionDefaultIfMissing && OperatingSystem.IsWindows())
        {
            // The service runs as LocalSystem, so it can write the machine-scope policy even when
            // the desktop or installer could not. Provision once, then report the real state.
            EnforcementPolicyProvisioner.EnsureMachineDefault(policyPath: _policyPath);
        }

        var policy = LoadPolicy();
        var summary = _journal.Summarize();

        return new EnforcementStatusDto
        {
            Enabled = policy.Enabled && policy.Evaluator is not null,
            Revision = policy.Revision,
            AgentCount = policy.Policy?.Agents.Count ?? 0,
            RuleCount = policy.Policy?.Agents.Sum(agent => agent.Rules.Count) ?? 0,
            ProtectedResourceCount = policy.Policy?.ProtectedResources.Count ?? 0,
            Error = policy.Error,
            ReceiptCount = summary.Total,
            HostDenySentCount = summary.HostDenySent,
            HostDenyVerifiedCount = summary.HostDenyVerified,
            GuardUnavailableCount = summary.GuardUnavailable,
            FailedOpenCount = summary.FailedOpen,
            ChainValid = summary.ChainValid,
        };
    }

    /// <summary>Read-only snapshot of redacted hash-chained enforcement receipts.</summary>
    public EnforcementReceiptsSnapshotDto GetReceipts()
    {
        var items = _journal.Snapshot();
        var valid = _journal.VerifyChain();

        var dtos = items.Select(receipt => new EnforcementReceiptDto
        {
            Schema = receipt.Schema,
            EventId = receipt.EventId,
            RequestId = receipt.RequestId,
            PolicyRevision = receipt.PolicyRevision,
            HostAdapter = receipt.HostAdapter,
            HostVersion = receipt.HostVersion,
            ActionKind = receipt.ActionKind.ToString(),
            DecisionSource = receipt.DecisionSource,
            IndicatorRef = receipt.IndicatorRef,
            RequestedDecision = receipt.RequestedDecision.ToString(),
            Boundary = EnforcementReceiptTokens.ToBoundaryToken(receipt.Boundary),
            Result = receipt.ResultToken,
            ObservedSideEffect = EnforcementReceiptTokens.ToSideEffectToken(receipt.ObservedSideEffect),
            VerifiedBy = receipt.VerifiedBy,
            TimestampUtc = receipt.TimestampUtc,
            PreviousHash = receipt.PreviousHash,
            IntegrityHash = receipt.IntegrityHash,
        }).ToArray();

        return new EnforcementReceiptsSnapshotDto
        {
            ChainValid = valid,
            Total = dtos.Length,
            Receipts = dtos,
        };
    }

    /// <summary>
    /// Evaluates one request. The caller identity comes from the authenticated pipe connection; an
    /// empty identity is rejected. Returned strength is observation unless the caller proved a host
    /// deny on this exact host and version.
    /// </summary>
    public Task<EnforcementVerdictDto> EvaluateAsync(
        EnforcementEvaluateRequest request,
        string actorSid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var kindParsed = TryParseKind(request.Kind, out var kind);
        var hostAdapter = string.IsNullOrWhiteSpace(request.HostAdapter)
            ? request.AgentId
            : request.HostAdapter;
        var timestamp = request.UtcTime == default ? DateTimeOffset.UtcNow : request.UtcTime;

        if (string.IsNullOrWhiteSpace(actorSid))
        {
            var verdict = Unavailable(
                request, "policy:unauthenticated", EnforcementReasonCodes.Unauthenticated, timestamp);
            var receipt = RecordReceipt(
                request,
                policyDigest: "0",
                hostAdapter,
                kind,
                verdict,
                EnforcementBoundaryKind.None,
                EnforcementReceiptResult.GuardUnavailable);
            return Task.FromResult(verdict with { ReceiptResult = receipt.ResultToken });
        }

        if (!kindParsed || !IsWellFormed(request))
        {
            var verdict = Unavailable(
                request, "policy:invalid-request", EnforcementReasonCodes.InvalidRequest, timestamp);
            var receipt = RecordReceipt(
                request,
                policyDigest: "0",
                hostAdapter,
                kind,
                verdict,
                EnforcementBoundaryKind.None,
                EnforcementReceiptResult.GuardUnavailable);
            return Task.FromResult(verdict with { ReceiptResult = receipt.ResultToken });
        }

        var policy = LoadPolicy();
        if (policy.Error is not null)
        {
            var verdict = Unavailable(
                request, "policy:invalid", EnforcementReasonCodes.PolicyInvalid, timestamp);
            var receipt = RecordReceipt(
                request,
                policy.Digest,
                hostAdapter,
                kind,
                verdict,
                EnforcementBoundaryKind.None,
                EnforcementReceiptResult.GuardUnavailable);
            return Task.FromResult(verdict with { ReceiptResult = receipt.ResultToken });
        }

        if (!policy.Enabled || policy.Evaluator is null)
        {
            var verdict = Unavailable(
                request, "policy:disabled", EnforcementReasonCodes.Disabled, timestamp);
            var receipt = RecordReceipt(
                request,
                policy.Digest,
                hostAdapter,
                kind,
                verdict,
                EnforcementBoundaryKind.None,
                EnforcementReceiptResult.GuardUnavailable);
            return Task.FromResult(verdict with { ReceiptResult = receipt.ResultToken });
        }

        var action = new AgentActionRequest
        {
            RequestId = request.RequestId,
            AgentId = request.AgentId,
            SessionId = request.SessionId,
            Kind = kind,
            Target = request.Target,
            ProcessPath = request.ProcessPath,
            ParentRequestId = request.ParentRequestId,
            UtcTime = timestamp,
        };

        var fingerprint = Fingerprint(action, policy.Revision);
        lock (_gate)
        {
            if (_fingerprints.TryGetValue(request.RequestId, out var existing) &&
                !string.Equals(existing, fingerprint, StringComparison.Ordinal))
            {
                var replayVerdict = Unavailable(
                    request, "policy:replay", EnforcementReasonCodes.ReplayMismatch, timestamp);
                var replayReceipt = RecordReceipt(
                    request,
                    policy.Digest,
                    hostAdapter,
                    kind,
                    replayVerdict,
                    EnforcementBoundaryKind.None,
                    EnforcementReceiptResult.GuardUnavailable);
                return Task.FromResult(replayVerdict with { ReceiptResult = replayReceipt.ResultToken });
            }

            if (!_fingerprints.ContainsKey(request.RequestId))
            {
                _fingerprints[request.RequestId] = fingerprint;
                _fingerprintOrder.Enqueue(request.RequestId);
                while (_fingerprintOrder.Count > MaximumRememberedRequests)
                {
                    _fingerprints.Remove(_fingerprintOrder.Dequeue());
                }
            }
        }

        var capabilities = new EnforcementCapabilities
        {
            Strength = request.HostSupportsDeny
                ? EnforcementStrength.HostHook
                : EnforcementStrength.Observation,
            HostSupportsDeny = request.HostSupportsDeny,
        };

        var guard = new BlackboxGuardSignal
        {
            IsAvailable = request.GuardAvailable,
            IsBlock = request.GuardBlock,
            SignalId = request.GuardSignalId,
            CommunityOnly = request.CommunityOnly,
        };

        var evaluated = policy.Evaluator.Evaluate(action, capabilities, guard);
        var (boundary, receiptResult) = ClassifyVerdict(evaluated);

        var verdictDto = new EnforcementVerdictDto
        {
            RequestId = evaluated.RequestId,
            Decision = LowerCamel(evaluated.Decision.ToString()),
            RuleId = evaluated.RuleId,
            ReasonCode = evaluated.ReasonCode,
            AvailableStrength = LowerCamel(evaluated.AvailableStrength.ToString()),
            RequireUserApproval = evaluated.RequireUserApproval,
            CanEnforce = evaluated.CanEnforce,
            BlackboxSignalId = evaluated.BlackboxSignalId,
            EvaluatedUtc = evaluated.EvaluatedUtc,
            PolicyRevision = policy.Revision,
        };

        var recordedReceipt = RecordReceipt(
            request,
            policy.Digest,
            hostAdapter,
            kind,
            verdictDto,
            boundary,
            receiptResult);

        return Task.FromResult(verdictDto with { ReceiptResult = recordedReceipt.ResultToken });
    }

    /// <summary>Default location of the opt-in policy file (machine scope: the service is LocalSystem).</summary>
    public static string DefaultPolicyPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Axiom",
        "enforcement-policy.json");

    private EnforcementReceiptV1 RecordReceipt(
        EnforcementEvaluateRequest request,
        string policyDigest,
        string? hostAdapter,
        AgentActionKind kind,
        EnforcementVerdictDto verdict,
        EnforcementBoundaryKind boundary,
        EnforcementReceiptResult result)
    {
        var requestedDecision = Enum.TryParse<EnforcementDecision>(
            verdict.Decision, ignoreCase: true, out var parsed)
            ? parsed
            : EnforcementDecision.Unavailable;

        var safeRequestId = string.IsNullOrWhiteSpace(request.RequestId) ? "invalid" : request.RequestId;
        var safeHost = string.IsNullOrWhiteSpace(hostAdapter) ? "unknown" : hostAdapter;

        var receipt = EnforcementReceiptV1.Create(
            eventId: $"{safeRequestId}:{verdict.ReasonCode}",
            requestId: safeRequestId,
            policyRevision: policyDigest,
            hostAdapter: safeHost,
            hostVersion: request.HostVersion,
            actionKind: kind,
            decisionSource: string.Equals(verdict.ReasonCode, EnforcementReasonCodes.CommunityAdvisoryOnly, StringComparison.Ordinal)
                ? "community_advisory"
                : verdict.RuleId,
            rawTargetOrIndicator: request.Target ?? request.ProcessPath,
            requestedDecision: requestedDecision,
            boundary: boundary,
            result: result,
            observedSideEffect: EnforcementObservedSideEffect.Unknown,
            verifiedBy: null,
            timestampUtc: verdict.EvaluatedUtc);

        _journal.TryAppend(receipt);
        return receipt;
    }

    private static (EnforcementBoundaryKind Boundary, EnforcementReceiptResult Result) ClassifyVerdict(
        AgentActionVerdict verdict)
    {
        if (verdict.Decision == EnforcementDecision.Unavailable)
        {
            return (EnforcementBoundaryKind.None, EnforcementReceiptResult.GuardUnavailable);
        }

        if (verdict.Decision == EnforcementDecision.Block)
        {
            return verdict.CanEnforce
                ? (EnforcementBoundaryKind.HostHook, EnforcementReceiptResult.HostDenySent)
                : (EnforcementBoundaryKind.DetectorOnly, EnforcementReceiptResult.DenyRequested);
        }

        if (verdict.Decision == EnforcementDecision.Audit)
        {
            return verdict.AvailableStrength == EnforcementStrength.HostHook
                ? (EnforcementBoundaryKind.HostHook, EnforcementReceiptResult.AuditOnly)
                : (EnforcementBoundaryKind.DetectorOnly, EnforcementReceiptResult.AuditOnly);
        }

        return (EnforcementBoundaryKind.HostHook, EnforcementReceiptResult.Detected);
    }

    private CachedPolicy LoadPolicy()
    {
        if (!File.Exists(_policyPath))
        {
            return Remember(new CachedPolicy(
                DateTime.MinValue, 0, false, null, null, null, "0", "0"));
        }

        var info = new FileInfo(_policyPath);
        lock (_gate)
        {
            if (_cached is { } cached &&
                cached.LastWriteUtc == info.LastWriteTimeUtc &&
                cached.Length == info.Length)
            {
                return cached;
            }
        }

        try
        {
            var json = File.ReadAllText(_policyPath);
            var digest = EnforcementReceiptV1.ComputePolicyRevisionHash(json);
            var envelope = JsonSerializer.Deserialize<PolicyEnvelope>(json, IpcJson.Options);
            if (envelope is null)
            {
                return Remember(new CachedPolicy(
                    info.LastWriteTimeUtc, info.Length, false, null, null,
                    "Policy file is empty or invalid.", "0", digest));
            }

            var revision = string.IsNullOrWhiteSpace(envelope.Policy.Version)
                ? "0"
                : envelope.Policy.Version;

            if (!envelope.Enabled)
            {
                return Remember(new CachedPolicy(
                    info.LastWriteTimeUtc, info.Length, false, envelope.Policy, null, null, revision, digest));
            }

            var problems = EnforcementPolicyValidator.Validate(envelope.Policy);
            if (problems.Count > 0)
            {
                return Remember(new CachedPolicy(
                    info.LastWriteTimeUtc, info.Length, false, null, null,
                    string.Join("; ", problems), revision, digest));
            }

            var evaluator = new EnforcementPolicyEvaluator(envelope.Policy);
            return Remember(new CachedPolicy(
                info.LastWriteTimeUtc, info.Length, true, envelope.Policy, evaluator, null, revision, digest));
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return Remember(new CachedPolicy(
                info.LastWriteTimeUtc, info.Length, false, null, null, exception.Message, "0", "0"));
        }
    }

    private CachedPolicy Remember(CachedPolicy policy)
    {
        lock (_gate)
        {
            _cached = policy;
        }

        return policy;
    }

    private static bool TryParseKind(string? value, out AgentActionKind kind) =>
        Enum.TryParse(value, ignoreCase: true, out kind) && Enum.IsDefined(kind);

    private static bool IsWellFormed(EnforcementEvaluateRequest request) =>
        IsBounded(request.RequestId, MaximumIdentityLength, required: true) &&
        IsBounded(request.AgentId, MaximumIdentityLength, required: true) &&
        IsBounded(request.SessionId, MaximumIdentityLength, required: false) &&
        IsBounded(request.ParentRequestId, MaximumIdentityLength, required: false) &&
        IsBounded(request.GuardSignalId, MaximumIdentityLength, required: false) &&
        IsBounded(request.Target, MaximumTargetLength, required: false) &&
        IsBounded(request.ProcessPath, MaximumTargetLength, required: false);

    private static bool IsBounded(string? value, int maximum, bool required) =>
        required
            ? !string.IsNullOrWhiteSpace(value) && value.Length <= maximum
            : value is null || value.Length <= maximum;

    private static string Fingerprint(AgentActionRequest request, string revision) => string.Join(
        '|',
        request.AgentId,
        request.Kind.ToString(),
        request.Target ?? string.Empty,
        request.ProcessPath ?? string.Empty,
        revision);

    private static EnforcementVerdictDto Unavailable(
        EnforcementEvaluateRequest request,
        string ruleId,
        string reasonCode,
        DateTimeOffset evaluatedUtc) => new()
        {
            RequestId = string.IsNullOrWhiteSpace(request.RequestId) ? "invalid" : request.RequestId,
            Decision = "unavailable",
            RuleId = ruleId,
            ReasonCode = reasonCode,
            AvailableStrength = "observation",
            RequireUserApproval = false,
            CanEnforce = false,
            EvaluatedUtc = evaluatedUtc,
            PolicyRevision = null,
        };

    private static string LowerCamel(string value) =>
        string.IsNullOrEmpty(value) || char.IsLower(value[0])
            ? value
            : char.ToLowerInvariant(value[0]) + value[1..];

    private sealed record PolicyEnvelope
    {
        public bool Enabled { get; init; }

        public EnforcementPolicy Policy { get; init; } = new();
    }

    private sealed record CachedPolicy(
        DateTime LastWriteUtc,
        long Length,
        bool Enabled,
        EnforcementPolicy? Policy,
        EnforcementPolicyEvaluator? Evaluator,
        string? Error,
        string Revision,
        string Digest);
}
