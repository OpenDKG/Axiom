// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Enforcement;

/// <summary>
/// Kind of operation an agent asks Axiom to evaluate. The list is deliberately narrow: the engine
/// decides only about operations Axiom can name, and everything else is <see cref="Unknown"/>.
/// </summary>
public enum AgentActionKind
{
    ReadFile = 0,
    WriteFile = 1,
    DeleteFile = 2,
    ExecuteProcess = 3,
    NetworkConnect = 4,
    HttpRequest = 5,
    ToolCall = 6,
    PromptSubmit = 7,
    Unknown = 8,
}

/// <summary>Deterministic outcome requested by policy. It is not a claim that the host obeyed it.</summary>
public enum EnforcementDecision
{
    Allow = 0,
    Block = 1,
    Ask = 2,
    Audit = 3,
    Unavailable = 4,
}

/// <summary>
/// Strongest control that can actually carry out a decision on this host. <see cref="Observation"/>
/// means Axiom can only report; it must never be presented as an enforced block.
/// </summary>
public enum EnforcementStrength
{
    Observation = 0,
    HostHook = 1,
    TrustedBroker = 2,
    OsBoundary = 3,
}

/// <summary>User-selected behaviour for one agent.</summary>
public enum EnforcementMode
{
    /// <summary>Record decisions only; change nothing.</summary>
    Monitor = 0,

    /// <summary>Ask the user about operations that have no explicit rule.</summary>
    Ask = 1,

    /// <summary>Protected resources are asked about or blocked when no boundary can enforce them.</summary>
    ProtectSelectedOperations = 2,
}

/// <summary>Effect of one ordered policy rule.</summary>
public enum EnforcementRuleEffect
{
    Allow = 0,
    Ask = 1,
    Block = 2,
}

/// <summary>
/// One typed request from a host adapter. It carries identifiers only; callers must not put secrets,
/// prompts or full file contents into <see cref="Target"/>.
/// </summary>
public sealed record AgentActionRequest
{
    /// <summary>Unique request identifier. Duplicate values are answered idempotently.</summary>
    public required string RequestId { get; init; }

    /// <summary>Agent identity as reported by the host adapter.</summary>
    public required string AgentId { get; init; }

    /// <summary>Optional host session identifier.</summary>
    public string? SessionId { get; init; }

    /// <summary>Operation being requested.</summary>
    public required AgentActionKind Kind { get; init; }

    /// <summary>Path, host name or tool target; never a secret or file content.</summary>
    public string? Target { get; init; }

    /// <summary>Executable path of the process that performs the action, when known.</summary>
    public string? ProcessPath { get; init; }

    /// <summary>Optional parent request for chained tool calls.</summary>
    public string? ParentRequestId { get; init; }

    /// <summary>Observation time from the host adapter. The engine never reads the clock itself.</summary>
    public DateTimeOffset UtcTime { get; init; }
}

/// <summary>Boundary and host facts supplied by the caller for this evaluation.</summary>
public sealed record EnforcementCapabilities
{
    /// <summary>Strongest control available on this host right now.</summary>
    public EnforcementStrength Strength { get; init; } = EnforcementStrength.Observation;

    /// <summary>True only when the host has been proven to honour a deny response.</summary>
    public bool HostSupportsDeny { get; init; }
}

/// <summary>
/// Result of the optional Blackbox guard for this request. A block verdict is a signal, not proof
/// that the host obeyed it.
/// </summary>
public sealed record BlackboxGuardSignal
{
    /// <summary>False when the guard could not be consulted.</summary>
    public required bool IsAvailable { get; init; }

    /// <summary>True when the guard returned its documented block verdict.</summary>
    public bool IsBlock { get; init; }

    /// <summary>Guard-side identifier for audit correlation.</summary>
    public string? SignalId { get; init; }
}

/// <summary>Deterministic verdict for one request.</summary>
public sealed record AgentActionVerdict
{
    public required string RequestId { get; init; }

    public required EnforcementDecision Decision { get; init; }

    /// <summary>Rule that produced the decision, or a reserved engine identifier.</summary>
    public required string RuleId { get; init; }

    /// <summary>Stable reason code from <see cref="EnforcementReasonCodes"/>.</summary>
    public required string ReasonCode { get; init; }

    public required EnforcementStrength AvailableStrength { get; init; }

    public bool RequireUserApproval { get; init; }

    public string? BlackboxSignalId { get; init; }

    /// <summary>Copied from the request so that identical inputs give identical verdicts.</summary>
    public DateTimeOffset EvaluatedUtc { get; init; }

    /// <summary>
    /// True only when the decision can be carried out by a boundary that actually exists. A block
    /// with <see cref="EnforcementStrength.Observation"/> is a request, not a verified outcome.
    /// </summary>
    public bool CanEnforce =>
        Decision is EnforcementDecision.Allow or EnforcementDecision.Audit
        || AvailableStrength != EnforcementStrength.Observation;
}

/// <summary>Stable reason codes; they are persisted in audit records.</summary>
public static class EnforcementReasonCodes
{
    public const string InvalidRequest = "ENF-INVALID-REQUEST";
    public const string MetricBound = "ENF-METRIC-BOUND";
    public const string ProtectedResource = "ENF-PROTECTED-RESOURCE";
    public const string ProtectedUnenforceable = "ENF-PROTECTED-UNENFORCEABLE";
    public const string ProtectedObserved = "ENF-PROTECTED-OBSERVED";
    public const string GuardBlock = "ENF-GUARD-BLOCK";
    public const string RuleBlock = "ENF-RULE-BLOCK";
    public const string RuleAsk = "ENF-RULE-ASK";
    public const string RuleAllow = "ENF-RULE-ALLOW";
    public const string NoRuleMonitor = "ENF-NO-RULE-MONITOR";
    public const string NoRuleAsk = "ENF-NO-RULE-ASK";
}
