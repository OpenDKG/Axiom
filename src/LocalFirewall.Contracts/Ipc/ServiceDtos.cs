// SPDX-License-Identifier: GPL-3.0-or-later
namespace LocalFirewall.Contracts.Ipc;

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
