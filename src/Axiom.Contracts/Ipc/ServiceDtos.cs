// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Contracts.Ipc;

/// <summary>Health snapshot returned by the service.</summary>
public sealed record ServiceHealth
{
    public required string Status { get; init; }

    public required long UptimeSeconds { get; init; }

    public required string SourceName { get; init; }

    public required double PollIntervalSeconds { get; init; }

    public DateTimeOffset? LastCaptureUtc { get; init; }

    public required int ConnectionCount { get; init; }

    public required int ProcessCount { get; init; }

    public IReadOnlyList<string> Limitations { get; init; } = [];

    public string? LastError { get; init; }
}

/// <summary>What this service build can do. Firewall writes stay false until FND-006.</summary>
public sealed record ServiceCapabilities
{
    public required int ProtocolVersion { get; init; }

    public required IReadOnlyList<string> Commands { get; init; }

    public required bool Monitoring { get; init; }

    public required bool FirewallWrites { get; init; }

    public required string Milestone { get; init; }
}

/// <summary>Read-only view of the host firewall capability and rules owned by Axiom.</summary>
public sealed record FirewallRulesSnapshot
{
    public required FirewallCapabilityReport Capability { get; init; }

    public required IReadOnlyList<ManagedRule> Rules { get; init; }

    /// <summary>True only when the explicit write gate is open on the service.</summary>
    public bool WritesEnabled { get; init; }
}

/// <summary>Reference to one managed rule for remove/verify commands.</summary>
public sealed record RuleReference
{
    public required Guid ManagedRuleId { get; init; }
}
