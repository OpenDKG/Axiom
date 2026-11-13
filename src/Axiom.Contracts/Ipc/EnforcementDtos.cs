// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Ipc;

/// <summary>
/// One bounded pre-action request from a host adapter. It carries identifiers only; never prompts,
/// file contents, secrets or command output. The caller authenticates as the same Windows user over
/// the local named pipe; no remote or unauthenticated transport is accepted.
/// </summary>
public sealed record EnforcementEvaluateRequest
{
    /// <summary>Unique per action. Reusing it for a different action is rejected.</summary>
    public required string RequestId { get; init; }

    /// <summary>Agent identity as reported by the host adapter, for example "opencode".</summary>
    public required string AgentId { get; init; }

    public string? SessionId { get; init; }

    /// <summary>Operation kind, parsed against the Axiom action-kind names, for example "readFile".</summary>
    public required string Kind { get; init; }

    /// <summary>Path, host name or tool target; never a secret or file content.</summary>
    public string? Target { get; init; }

    /// <summary>Executable path of the process that performs the action, when known.</summary>
    public string? ProcessPath { get; init; }

    public string? ParentRequestId { get; init; }

    /// <summary>Observation time from the host adapter.</summary>
    public DateTimeOffset UtcTime { get; init; }

    /// <summary>False when Blackbox could not be consulted.</summary>
    public bool GuardAvailable { get; init; }

    /// <summary>True only when Blackbox returned its documented block verdict.</summary>
    public bool GuardBlock { get; init; }

    public string? GuardSignalId { get; init; }

    /// <summary>
    /// True only when this host version has been proven to honour the adapter's deny response.
    /// Without it the decision is observation strength and must not be shown as enforced.
    /// </summary>
    public bool HostSupportsDeny { get; init; }
}

/// <summary>The policy decision and its honest strength. It is not proof that the host obeyed it.</summary>
public sealed record EnforcementVerdictDto
{
    public required string RequestId { get; init; }

    /// <summary>allow, block, ask, audit or unavailable.</summary>
    public required string Decision { get; init; }

    public required string RuleId { get; init; }

    public required string ReasonCode { get; init; }

    /// <summary>observation, hostHook, trustedBroker or osBoundary.</summary>
    public required string AvailableStrength { get; init; }

    public bool RequireUserApproval { get; init; }

    /// <summary>True only when the decision can actually be carried out by an existing boundary.</summary>
    public bool CanEnforce { get; init; }

    public string? BlackboxSignalId { get; init; }

    public required DateTimeOffset EvaluatedUtc { get; init; }

    public string? PolicyRevision { get; init; }
}

/// <summary>Off-by-default state of the offline enforcement policy.</summary>
public sealed record EnforcementStatusDto
{
    public required bool Enabled { get; init; }

    public required string Revision { get; init; }

    public required int AgentCount { get; init; }

    public required int RuleCount { get; init; }

    public required int ProtectedResourceCount { get; init; }

    /// <summary>Present only when the policy file exists but is unusable.</summary>
    public string? Error { get; init; }
}
