// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Monitoring;

public enum TransportProtocol
{
    Tcp = 0,
    Udp = 1,
}

public enum ConnectionDirection
{
    Outbound = 0,
    Inbound = 1,

    /// <summary>
    /// Not derivable from the owner table (for example a UDP endpoint without a remote address).
    /// The UI must show this as unknown instead of guessing a direction.
    /// </summary>
    Unknown = 2,
}

/// <summary>
/// What Axiom knows about the rule state of a connection. Values are deliberately
/// explicit so the UI can never render an unverified connection as "allowed".
/// </summary>
public enum ConnectionRuleStatus
{
    Unknown = 0,
    NoOwnedRule = 1,
    BlockedByOwnedRule = 2,
    BlockedByExternalPolicy = 3,
    AllowedByDefaultPolicy = 4,
    AllowedByOwnedRule = 5,
}

/// <summary>Attribution quality of a single observation.</summary>
public enum DataQuality
{
    Unknown = 0,
    Observed = 1,
    Partial = 2,
}

/// <summary>
/// One connection observed in the Windows owner tables (FND-002). PIDs and endpoints come from
/// the OS; byte rates stay unknown until ETW measurement exists (FND-004).
/// </summary>
public sealed record LiveConnection
{
    public required string AppDisplayName { get; init; }

    /// <summary>Resolved executable path, or an empty string when Windows does not expose it.</summary>
    public required string AppPath { get; init; }

    public required int ProcessId { get; init; }

    public required TransportProtocol Protocol { get; init; }

    public required string LocalEndpoint { get; init; }

    /// <summary>Remote endpoint, or an em dash when the owner table does not provide one.</summary>
    public required string RemoteEndpoint { get; init; }

    public required string State { get; init; }

    public required ConnectionDirection Direction { get; init; }

    /// <summary>Adapter name; empty in FND-002 because the owner table has no interface field.</summary>
    public required string InterfaceName { get; init; }

    /// <summary>First poll in which this application observed the connection, not the TCP start time.</summary>
    public required DateTimeOffset FirstObservedUtc { get; init; }

    /// <summary>Null means "not measured"; IP Helper cannot provide byte counts.</summary>
    public double? EstimatedUploadBytesPerSecond { get; init; }

    /// <summary>Null means "not measured"; IP Helper cannot provide byte counts.</summary>
    public double? EstimatedDownloadBytesPerSecond { get; init; }

    public bool IsLoopback { get; init; }

    public bool IsNew { get; init; }

    public ConnectionRuleStatus RuleStatus { get; init; } = ConnectionRuleStatus.Unknown;

    public DataQuality Quality { get; init; } = DataQuality.Observed;

    /// <summary>Immediate parent PID, when the Windows process table exposes it.</summary>
    public int? ParentProcessId { get; init; }

    public string ParentProcessName { get; init; } = string.Empty;

    /// <summary>Immediate parent chain, oldest last.</summary>
    public string ParentChain { get; init; } = string.Empty;

    /// <summary>Sanitised command line from the elevated service, or empty when unavailable.</summary>
    public string CommandLine { get; init; } = string.Empty;

    /// <summary>Authenticode signer subject, or empty when unsigned/unreadable.</summary>
    public string SignerName { get; init; } = string.Empty;

    /// <summary>Valid, Untrusted, Unsigned or Unavailable.</summary>
    public string SignatureStatus { get; init; } = "Unavailable";

    public string ProductName { get; init; } = string.Empty;

    public string FileVersion { get; init; } = string.Empty;

    /// <summary>Windows service names hosted by this process, usually only for svchost.exe.</summary>
    public string HostedServices { get; init; } = string.Empty;

    /// <summary>Windows service names hosted by the immediate parent, when it is svchost.exe.</summary>
    public string ParentHostedServices { get; init; } = string.Empty;
}
