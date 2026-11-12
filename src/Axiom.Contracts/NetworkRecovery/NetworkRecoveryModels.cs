// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;

namespace Axiom.Contracts.NetworkRecovery;

/// <summary>
/// How Windows obtains DNS for one address family of one adapter. <see cref="Automatic"/> means the
/// adapter receives servers from DHCP (or another automatic source) and is restored by clearing the
/// static override; <see cref="Static"/> means the captured servers are the authoritative config.
/// </summary>
public enum NetworkDnsMode
{
    Automatic = 0,
    Static = 1,
}

/// <summary>Per-family DNS configuration captured before Axiom changes an adapter.</summary>
public sealed record NetworkAdapterDnsState
{
    public required Guid AdapterId { get; init; }

    public required string InterfaceAlias { get; init; }

    public required string Description { get; init; }

    public required NetworkDnsMode Ipv4Mode { get; init; }

    public required NetworkDnsMode Ipv6Mode { get; init; }

    /// <summary>Static IPv4 servers only; empty when <see cref="Ipv4Mode"/> is automatic.</summary>
    public IReadOnlyList<string> Ipv4Servers { get; init; } = [];

    /// <summary>Static IPv6 servers only; empty when <see cref="Ipv6Mode"/> is automatic.</summary>
    public IReadOnlyList<string> Ipv6Servers { get; init; } = [];
}

/// <summary>
/// A firewall rule captured as Axiom-owned. Identity is the managed rule id plus direction; the
/// captured group is the OS metadata that, together with the strict <c>Axiom::{id}::{OUT|IN}</c>
/// name, proves ownership. Restore re-reads this evidence before removing anything.
/// </summary>
public sealed record NetworkOwnedRuleState
{
    public required Guid ManagedRuleId { get; init; }

    public required FirewallDirection Direction { get; init; }

    public required string OwnershipGroup { get; init; }
}

/// <summary>
/// Last known-good network state, persisted by the elevated service before Axiom changes DNS or
/// firewall rules. It contains no secrets: adapter ids, DNS addresses and Axiom rule identities.
/// </summary>
public sealed record NetworkRecoverySnapshot
{
    public const int CurrentFormatVersion = 2;

    public int FormatVersion { get; init; } = CurrentFormatVersion;

    public required DateTimeOffset CapturedUtc { get; init; }

    /// <summary>Whether Axiom Shield was intentionally enabled when the snapshot was taken.</summary>
    public required bool ProtectionWasActive { get; init; }

    public IReadOnlyList<NetworkAdapterDnsState> Adapters { get; init; } = [];

    public IReadOnlyList<NetworkOwnedRuleState> Rules { get; init; } = [];
}

/// <summary>Result of reading the snapshot file. A valid file may legitimately contain no items.</summary>
public enum NetworkRecoverySnapshotReadStatus
{
    Missing = 0,
    Valid = 1,
    Corrupt = 2,
    Unreadable = 3,
}

public sealed record NetworkRecoverySnapshotRead(
    NetworkRecoverySnapshotReadStatus Status,
    NetworkRecoverySnapshot? Snapshot,
    string? Error)
{
    public static NetworkRecoverySnapshotRead Missing { get; } =
        new(NetworkRecoverySnapshotReadStatus.Missing, null, null);

    public static NetworkRecoverySnapshotRead Valid(NetworkRecoverySnapshot snapshot) =>
        new(NetworkRecoverySnapshotReadStatus.Valid, snapshot, null);

    public static NetworkRecoverySnapshotRead Corrupt(string error) =>
        new(NetworkRecoverySnapshotReadStatus.Corrupt, null, error);

    public static NetworkRecoverySnapshotRead Unreadable(string error) =>
        new(NetworkRecoverySnapshotReadStatus.Unreadable, null, error);
}

/// <summary>One safe, user-displayable recovery failure.</summary>
public sealed record NetworkRecoveryProblem
{
    public required string Code { get; init; }

    public required string Message { get; init; }

    /// <summary>Adapter alias or rule identity the problem belongs to, when applicable.</summary>
    public string? Item { get; init; }
}

/// <summary>Overall outcome of an IPC network recovery operation.</summary>
public enum NetworkRecoveryStatus
{
    Succeeded = 0,
    AlreadyCaptured = 1,
    NoSnapshot = 2,
    SnapshotCorrupt = 3,
    NotAuthorized = 4,
    Unavailable = 5,
    Incompatible = 6,
    Busy = 7,
    PartialFailure = 8,
    Failed = 9,
}

public sealed record NetworkRecoveryCaptureResult
{
    public required NetworkRecoveryStatus Status { get; init; }

    public DateTimeOffset? CapturedUtc { get; init; }

    public bool ProtectionWasActive { get; init; }

    public int AdapterCount { get; init; }

    public int RuleCount { get; init; }

    public bool Persisted { get; init; }

    public IReadOnlyList<NetworkRecoveryProblem> Problems { get; init; } = [];
}

public sealed record NetworkRecoveryRestoreResult
{
    public required NetworkRecoveryStatus Status { get; init; }

    public int AdaptersRestored { get; init; }

    public int AdaptersVerified { get; init; }

    public int RulesRemoved { get; init; }

    public int RulesVerifiedAbsent { get; init; }

    /// <summary>True only when every captured item was read back in the restored state.</summary>
    public bool Verified { get; init; }

    public DateTimeOffset CompletedUtc { get; init; }

    public IReadOnlyList<NetworkRecoveryProblem> Problems { get; init; } = [];
}
