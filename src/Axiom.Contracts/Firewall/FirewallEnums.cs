// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Firewall;

/// <summary>Direction of a firewall rule, mirroring the Windows Firewall model.</summary>
public enum FirewallDirection
{
    Inbound = 0,
    Outbound = 1,
}

/// <summary>Action applied when a rule matches.</summary>
public enum FirewallAction
{
    Allow = 0,
    Block = 1,
}

/// <summary>
/// Windows Firewall network profiles. <see cref="FirewallProfile"/> is a flags enum so a
/// single rule can target more than one profile.
/// </summary>
[Flags]
public enum FirewallProfile
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
    All = Domain | Private | Public,
}

/// <summary>Protocol scope of a rule. <see cref="Any"/> is the Windows default.</summary>
public enum NetworkProtocol
{
    Any = 0,
    Tcp = 6,
    Udp = 17,
}

/// <summary>Persistence/enforcement state of a managed rule.</summary>
public enum RuleState
{
    Unknown = 0,
    Desired = 1,
    Pending = 2,
    Applied = 3,
    Failed = 4,
}

/// <summary>Availability of the underlying firewall policy adapter.</summary>
public enum FirewallCapabilityStatus
{
    Unknown = 0,
    Available = 1,
    Unavailable = 2,
    Degraded = 3,
}
