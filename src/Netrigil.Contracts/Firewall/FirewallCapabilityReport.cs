// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netrigil.Contracts.Firewall;

/// <summary>
/// Result of probing the platform firewall adapter. A <c>null</c> flag means "not probed",
/// never "supported". FND-001 reports <see cref="FirewallCapabilityStatus.Unavailable"/>.
/// </summary>
public sealed record FirewallCapabilityReport
{
    public required FirewallCapabilityStatus Status { get; init; }

    /// <summary>Short, user-presentable reason. Required when the adapter is not available.</summary>
    public string? Reason { get; init; }

    public bool? FirewallServiceRunning { get; init; }

    public bool? ManagedRulesReadable { get; init; }

    public int? ManagedRuleCount { get; init; }

    public DateTimeOffset ProbedUtc { get; init; } = DateTimeOffset.UtcNow;
}
