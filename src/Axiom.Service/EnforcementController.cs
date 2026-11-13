// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Core.Enforcement;

namespace Axiom.Service;

/// <summary>
/// Offline enforcement decision boundary. It loads a user-owned policy file, evaluates a bounded
/// request with the existing deterministic <see cref="EnforcementPolicyEvaluator"/> and returns an
/// honest verdict. It is off unless a valid policy file enables it, and it never writes user files,
/// contacts the network or turns a decision into a claim that a host obeyed it.
/// </summary>
public sealed class EnforcementController
{
    private const int MaximumIdentityLength = 128;
    private const int MaximumTargetLength = 4096;
    private const int MaximumRememberedRequests = 1024;

    private readonly string _policyPath;
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _fingerprints = new(StringComparer.Ordinal);
    private readonly Queue<string> _fingerprintOrder = new();

    private CachedPolicy? _cached;

    public EnforcementController()
        : this(DefaultPolicyPath())
    {
    }

    public EnforcementController(string policyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyPath);
        _policyPath = Path.GetFullPath(policyPath);
    }

    public string PolicyPath => _policyPath;

    /// <summary>Current policy state. Missing file means disabled, not an error.</summary>
    public EnforcementStatusDto GetStatus()
    {
        var policy = LoadPolicy();

        return new EnforcementStatusDto
        {
            Enabled = policy.Enabled && policy.Evaluator is not null,
            Revision = policy.Revision,
            AgentCount = policy.Policy?.Agents.Count ?? 0,
            RuleCount = policy.Policy?.Agents.Sum(agent => agent.Rules.Count) ?? 0,
            ProtectedResourceCount = policy.Policy?.ProtectedResources.Count ?? 0,
            Error = policy.Error,
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

        if (string.IsNullOrWhiteSpace(actorSid))
        {
            return Task.FromResult(Unavailable(
                request, "policy:unauthenticated", EnforcementReasonCodes.Unauthenticated));
        }

        if (!TryParseKind(request.Kind, out var kind) || !IsWellFormed(request))
        {
            return Task.FromResult(Unavailable(
                request, "policy:invalid-request", EnforcementReasonCodes.InvalidRequest));
        }

        var policy = LoadPolicy();
        if (policy.Error is not null)
        {
            return Task.FromResult(Unavailable(
                request, "policy:invalid", EnforcementReasonCodes.PolicyInvalid));
        }

        if (!policy.Enabled || policy.Evaluator is null)
        {
            return Task.FromResult(Unavailable(
                request, "policy:disabled", EnforcementReasonCodes.Disabled));
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
            UtcTime = request.UtcTime == default ? DateTimeOffset.UtcNow : request.UtcTime,
        };

        var fingerprint = Fingerprint(action, policy.Revision);
        lock (_gate)
        {
            if (_fingerprints.TryGetValue(request.RequestId, out var existing) &&
                !string.Equals(existing, fingerprint, StringComparison.Ordinal))
            {
                return Task.FromResult(Unavailable(
                    request, "policy:replay", EnforcementReasonCodes.ReplayMismatch));
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
        };

        var verdict = policy.Evaluator.Evaluate(action, capabilities, guard);

        return Task.FromResult(new EnforcementVerdictDto
        {
            RequestId = verdict.RequestId,
            Decision = LowerCamel(verdict.Decision.ToString()),
            RuleId = verdict.RuleId,
            ReasonCode = verdict.ReasonCode,
            AvailableStrength = LowerCamel(verdict.AvailableStrength.ToString()),
            RequireUserApproval = verdict.RequireUserApproval,
            CanEnforce = verdict.CanEnforce,
            BlackboxSignalId = verdict.BlackboxSignalId,
            EvaluatedUtc = verdict.EvaluatedUtc,
            PolicyRevision = policy.Revision,
        });
    }

    /// <summary>Default location of the opt-in policy file.</summary>
    public static string DefaultPolicyPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "enforcement-policy.json");

    private CachedPolicy LoadPolicy()
    {
        if (!File.Exists(_policyPath))
        {
            return Remember(new CachedPolicy(
                DateTime.MinValue, 0, false, null, null, null, "0"));
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
            var envelope = JsonSerializer.Deserialize<PolicyEnvelope>(json, IpcJson.Options);
            if (envelope is null)
            {
                return Remember(new CachedPolicy(
                    info.LastWriteTimeUtc, info.Length, false, null, null,
                    "Policy file is empty or invalid.", "0"));
            }

            var revision = string.IsNullOrWhiteSpace(envelope.Policy.Version)
                ? "0"
                : envelope.Policy.Version;

            if (!envelope.Enabled)
            {
                return Remember(new CachedPolicy(
                    info.LastWriteTimeUtc, info.Length, false, envelope.Policy, null, null, revision));
            }

            var problems = EnforcementPolicyValidator.Validate(envelope.Policy);
            if (problems.Count > 0)
            {
                return Remember(new CachedPolicy(
                    info.LastWriteTimeUtc, info.Length, false, null, null,
                    string.Join("; ", problems), revision));
            }

            var evaluator = new EnforcementPolicyEvaluator(envelope.Policy);
            return Remember(new CachedPolicy(
                info.LastWriteTimeUtc, info.Length, true, envelope.Policy, evaluator, null, revision));
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return Remember(new CachedPolicy(
                info.LastWriteTimeUtc, info.Length, false, null, null, exception.Message, "0"));
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
        string reasonCode) => new()
        {
            RequestId = request.RequestId,
            Decision = "unavailable",
            RuleId = ruleId,
            ReasonCode = reasonCode,
            AvailableStrength = "observation",
            RequireUserApproval = false,
            CanEnforce = false,
            EvaluatedUtc = request.UtcTime == default ? DateTimeOffset.UtcNow : request.UtcTime,
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
        string Revision);
}
