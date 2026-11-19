// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using System.IO;

namespace Axiom.Core.Enforcement;

/// <summary>Provenance of a requested OS-level network control rule.</summary>
public enum AgentNetworkPolicyOrigin
{
    LocalUserPolicy = 0,
    ExplicitOperatorApproval = 1,
    CommunitySignal = 2,
    PublicFeed = 3,
}

/// <summary>One bounded, reversible request to create an Axiom-owned outbound agent block rule.</summary>
public sealed record AgentFirewallRuleIntent
{
    public required string ExecutablePath { get; init; }

    public required string RemoteAddressOrCidr { get; init; }

    public string? RemotePorts { get; init; }

    public NetworkProtocol Protocol { get; init; } = NetworkProtocol.Tcp;

    public required AgentNetworkPolicyOrigin Origin { get; init; }

    public bool ExplicitlyAuthorizedByUser { get; init; }

    public required string ActorSid { get; init; }

    public string PolicyRevision { get; init; } = "0";
}

/// <summary>Result of validating whether an intent may materialize into an OS firewall rule.</summary>
public sealed record AgentFirewallPlanResult
{
    public required bool IsAllowedToWriteOsRule { get; init; }

    public string? RejectionReasonCode { get; init; }

    public string? RejectionMessage { get; init; }

    public RuleSpec? Spec { get; init; }
}

/// <summary>Measured evidence from a dual-destination network canary test.</summary>
public sealed record DualDestinationCanaryObservation(
    bool BlockedEndpointDenied,
    bool PermittedControlEndpointSucceeded,
    bool OsRuleReadbackVerified,
    string ChildProcessAttributionNote);

/// <summary>
/// Pure rule planner for Stage E4: converts only explicitly authorized local user rules into
/// narrowly scoped <see cref="RuleSpec"/> instances while refusing community/feed signals from
/// automatically modifying the OS firewall.
/// </summary>
public static class AgentFirewallRulePlanner
{
    public static AgentFirewallPlanResult BuildScopedBlockSpec(AgentFirewallRuleIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);

        if (intent.Origin is AgentNetworkPolicyOrigin.CommunitySignal or AgentNetworkPolicyOrigin.PublicFeed &&
            !intent.ExplicitlyAuthorizedByUser)
        {
            return Rejected(
                EnforcementReasonCodes.CommunityAdvisoryOnly,
                "Community and public-feed indicators remain advisory and cannot automatically create Windows Firewall rules.");
        }

        if (!intent.ExplicitlyAuthorizedByUser)
        {
            return Rejected(
                EnforcementReasonCodes.Disabled,
                "OS firewall rule creation requires explicit user authorization.");
        }

        if (string.IsNullOrWhiteSpace(intent.ExecutablePath) ||
            string.IsNullOrWhiteSpace(intent.RemoteAddressOrCidr) ||
            string.IsNullOrWhiteSpace(intent.ActorSid))
        {
            return Rejected(
                EnforcementReasonCodes.InvalidRequest,
                "Executable path, remote IP/CIDR scope, and caller SID are required.");
        }

        var normalizedRemote = intent.RemoteAddressOrCidr.Trim();
        var ruleId = RuleIdentity.ForAgentEndpoint(
            intent.ExecutablePath,
            FirewallDirection.Outbound,
            normalizedRemote,
            intent.RemotePorts);

        var spec = new RuleSpec
        {
            ManagedRuleId = ruleId,
            AppPath = intent.ExecutablePath.Trim(),
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            Protocol = intent.Protocol,
            RemoteAddresses = [normalizedRemote],
            RemotePorts = string.IsNullOrWhiteSpace(intent.RemotePorts) ? null : intent.RemotePorts.Trim(),
            CreatedBy = intent.ActorSid.Trim(),
            Description = "Axiom E4 scoped agent outbound control",
        };

        var validation = RuleSpecValidator.Validate(spec);
        if (!validation.IsValid)
        {
            return Rejected(
                EnforcementReasonCodes.InvalidRequest,
                string.Join("; ", validation.Errors.Select(error => $"{error.Code}: {error.Message}")));
        }

        return new AgentFirewallPlanResult
        {
            IsAllowedToWriteOsRule = true,
            Spec = spec,
        };
    }

    /// <summary>
    /// Builds an Axiom-owned outbound block for every destination of one executable (F-19 part C,
    /// per-process egress containment). Requires explicit user authorization and refuses Windows
    /// system binaries, so the rule cannot cut off the OS itself.
    /// </summary>
    public static AgentFirewallPlanResult BuildProcessEgressBlockSpec(
        string executablePath,
        string actorSid,
        AgentNetworkPolicyOrigin origin,
        bool explicitlyAuthorizedByUser)
    {
        if (origin is AgentNetworkPolicyOrigin.CommunitySignal or AgentNetworkPolicyOrigin.PublicFeed &&
            !explicitlyAuthorizedByUser)
        {
            return Rejected(
                EnforcementReasonCodes.CommunityAdvisoryOnly,
                "Community and public-feed indicators remain advisory and cannot automatically create Windows Firewall rules.");
        }

        if (!explicitlyAuthorizedByUser)
        {
            return Rejected(
                EnforcementReasonCodes.Disabled,
                "A per-process egress block requires explicit user authorization.");
        }

        if (string.IsNullOrWhiteSpace(executablePath) || string.IsNullOrWhiteSpace(actorSid))
        {
            return Rejected(
                EnforcementReasonCodes.InvalidRequest,
                "Executable path and caller SID are required.");
        }

        var path = executablePath.Trim();
        if (!IsAbsolutePath(path))
        {
            return Rejected(
                EnforcementReasonCodes.InvalidRequest,
                "The executable path must be absolute.");
        }

        if (IsWindowsSystemBinaryUnder(path, @"C:\Windows") ||
            IsWindowsSystemBinaryUnder(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows)))
        {
            return Rejected(
                EnforcementReasonCodes.InvalidRequest,
                "Refusing to block egress for a Windows system binary.");
        }

        var ruleId = RuleIdentity.ForAgentEndpoint(path, FirewallDirection.Outbound, "any");
        var spec = new RuleSpec
        {
            ManagedRuleId = ruleId,
            AppPath = path,
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            Protocol = NetworkProtocol.Any,
            RemoteAddresses = [],
            RemotePorts = null,
            CreatedBy = actorSid.Trim(),
            Description = "Axiom E4 per-process agent egress block",
        };

        var validation = RuleSpecValidator.Validate(spec);
        if (!validation.IsValid)
        {
            return Rejected(
                EnforcementReasonCodes.InvalidRequest,
                string.Join("; ", validation.Errors.Select(error => $"{error.Code}: {error.Message}")));
        }

        return new AgentFirewallPlanResult
        {
            IsAllowedToWriteOsRule = true,
            Spec = spec,
        };
    }

    private static AgentFirewallPlanResult Rejected(string reasonCode, string message) => new()
    {
        IsAllowedToWriteOsRule = false,
        RejectionReasonCode = reasonCode,
        RejectionMessage = message,
        Spec = null,
    };

    /// <summary>
    /// Absolute under the running OS or under Windows rules; the same rule spec reaches the Linux
    /// adapter, where <see cref="Path.IsPathFullyQualified(string)"/> rejects <c>C:\…</c>.
    /// </summary>
    private static bool IsAbsolutePath(string path) =>
        Path.IsPathFullyQualified(path) ||
        (path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/'));

    /// <summary>
    /// Windows system binaries are refused on every host: the check must not depend on the host's
    /// <see cref="Environment.SpecialFolder.Windows"/> (empty off Windows).
    /// </summary>
    private static bool IsWindowsSystemBinaryUnder(string path, string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var prefix = directory.TrimEnd('\\', '/');
        return path.StartsWith(prefix + "\\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase);
    }
}
