// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Protection;

public enum ProtectionDecisionAction
{
    Block = 0,
    Allow = 1,
}

/// <summary>An outbound application that has no recorded decision yet.</summary>
public sealed record ProtectionPendingApp
{
    public required string AppPath { get; init; }

    public required string AppName { get; init; }

    public required int SocketCount { get; init; }

    public required DateTimeOffset FirstObservedUtc { get; init; }

    public bool IsAgent { get; init; }

    /// <summary>
    /// Remote endpoints observed for this executable, newest snapshot only. Empty when Windows did
    /// not report them. This is context for the operator, not a verdict.
    /// </summary>
    public IReadOnlyList<string> RemoteEndpoints { get; init; } = [];
}

/// <summary>A decision the operator made for one executable path.</summary>
public sealed record ProtectionDecision
{
    public required string AppPath { get; init; }

    public required string AppName { get; init; }

    public required ProtectionDecisionAction Action { get; init; }

    public required DateTimeOffset DecidedUtc { get; init; }

    /// <summary>True when the rule was created by the agent internet lockdown.</summary>
    public bool IsAgentLockdown { get; init; }

    public Guid? ManagedRuleId { get; init; }
}

/// <summary>Everything the Firewall page and the status bar need to render protection state.</summary>
public sealed record ProtectionStatus
{
    public required bool Enabled { get; init; }

    /// <summary>True only when the service runs outside the interactive session (a Windows service).</summary>
    public required bool ServiceElevated { get; init; }

    public required bool WriteGateOpen { get; init; }

    public required string AccountName { get; init; }

    public required string DefaultPolicy { get; init; }

    public required IReadOnlyList<ProtectionPendingApp> Pending { get; init; }

    public required IReadOnlyList<ProtectionDecision> Decisions { get; init; }

    /// <summary>Agent executables currently present in the live snapshot.</summary>
    public required IReadOnlyList<string> AgentPaths { get; init; }

    public bool AgentLockdown { get; init; }

    public int OwnedRuleCount { get; init; }

    public string? LastError { get; init; }
}

public sealed record ProtectionEnableRequest
{
    public string DefaultPolicy { get; init; } = "ask";
}

public sealed record ProtectionDecideRequest
{
    public required string AppPath { get; init; }

    public required string AppName { get; init; }

    public required ProtectionDecisionAction Action { get; init; }
}

public sealed record ProtectionLockdownRequest
{
    public bool Enabled { get; init; }
}
