// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Enforcement;

/// <summary>One ordered rule for a single agent.</summary>
public sealed record EnforcementRule
{
    /// <summary>Stable identifier persisted in audit records.</summary>
    public required string RuleId { get; init; }

    /// <summary>What the rule asks Axiom to decide.</summary>
    public required EnforcementRuleEffect Effect { get; init; }

    /// <summary>Kind filter; <c>null</c> matches every kind.</summary>
    public AgentActionKind? Kind { get; init; }

    /// <summary>
    /// Path prefix or host scope. Windows separators are normalised before comparison; a host scope
    /// also matches its subdomains.
    /// </summary>
    public string? TargetScope { get; init; }
}

/// <summary>
/// A resource the user marked as protected. It is never an OS claim: without a real boundary the
/// engine reports the decision as unenforceable.
/// </summary>
public sealed record ProtectedResource
{
    /// <summary>Stable identifier shown in audit records and the UI.</summary>
    public required string ResourceId { get; init; }

    /// <summary>Path prefix or host scope that defines the resource.</summary>
    public required string Scope { get; init; }

    /// <summary>Kinds covered by this resource; empty means every kind.</summary>
    public IReadOnlyList<AgentActionKind> Kinds { get; init; } = [];
}

/// <summary>Per-agent policy. Agents without an entry use monitor mode and inherit no allow rules.</summary>
public sealed record AgentEnforcementPolicy
{
    public required string AgentId { get; init; }

    public EnforcementMode Mode { get; init; } = EnforcementMode.Monitor;

    /// <summary>Rules are evaluated in order; the first matching rule decides.</summary>
    public IReadOnlyList<EnforcementRule> Rules { get; init; } = [];
}

/// <summary>Offline, user-owned policy. It contains no network, reputation or DKG input by design.</summary>
public sealed record EnforcementPolicy
{
    public IReadOnlyList<AgentEnforcementPolicy> Agents { get; init; } = [];

    public IReadOnlyList<ProtectedResource> ProtectedResources { get; init; } = [];

    /// <summary>Policy revision copied into audit records by callers.</summary>
    public string Version { get; init; } = "1";
}

/// <summary>Bounds and consistency checks applied before a policy is used.</summary>
public static class EnforcementPolicyValidator
{
    /// <summary>Upper bound on rules across all agents.</summary>
    public const int MaximumRules = 512;

    /// <summary>Upper bound on any identifier or scope string.</summary>
    public const int MaximumTextLength = 1024;

    /// <summary>Returns human-readable problems; an empty list means the policy is usable.</summary>
    public static IReadOnlyList<string> Validate(EnforcementPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var problems = new List<string>();
        var agentIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ruleIds = new HashSet<string>(StringComparer.Ordinal);
        var resourceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ruleCount = 0;

        foreach (var agent in policy.Agents)
        {
            if (agent is null)
            {
                problems.Add("Agent entry is null.");
                continue;
            }

            if (string.IsNullOrWhiteSpace(agent.AgentId) || agent.AgentId.Length > MaximumTextLength)
            {
                problems.Add("Agent identifier is empty or too long.");
            }
            else if (!agentIds.Add(agent.AgentId))
            {
                problems.Add($"Duplicate agent identifier '{agent.AgentId}'.");
            }

            foreach (var rule in agent.Rules)
            {
                ruleCount++;
                if (rule is null)
                {
                    problems.Add($"Agent '{agent.AgentId}' contains a null rule.");
                    continue;
                }

                if (string.IsNullOrWhiteSpace(rule.RuleId) || rule.RuleId.Length > MaximumTextLength)
                {
                    problems.Add($"Agent '{agent.AgentId}' has a rule with an empty or oversized identifier.");
                }
                else if (!ruleIds.Add(rule.RuleId))
                {
                    problems.Add($"Duplicate rule identifier '{rule.RuleId}'.");
                }

                if (rule.TargetScope?.Length > MaximumTextLength)
                {
                    problems.Add($"Rule '{rule.RuleId}' scope is too long.");
                }
            }
        }

        foreach (var resource in policy.ProtectedResources)
        {
            if (resource is null)
            {
                problems.Add("Protected resource entry is null.");
                continue;
            }

            if (string.IsNullOrWhiteSpace(resource.ResourceId) || resource.ResourceId.Length > MaximumTextLength)
            {
                problems.Add("Protected resource identifier is empty or too long.");
            }
            else if (!resourceIds.Add(resource.ResourceId))
            {
                problems.Add($"Duplicate protected resource identifier '{resource.ResourceId}'.");
            }

            if (string.IsNullOrWhiteSpace(resource.Scope) || resource.Scope.Length > MaximumTextLength)
            {
                problems.Add($"Protected resource '{resource.ResourceId}' has an empty or oversized scope.");
            }
        }

        if (ruleCount > MaximumRules)
        {
            problems.Add($"Policy contains {ruleCount} rules; the maximum is {MaximumRules}.");
        }

        if (policy.Version.Length > MaximumTextLength)
        {
            problems.Add("Policy version string is too long.");
        }

        return problems;
    }
}

/// <summary>Scope matching shared by rules and protected resources.</summary>
internal static class EnforcementScopeMatcher
{
    internal static bool MatchesTarget(string? scope, AgentActionRequest request) =>
        MatchesScope(scope, request.Target) || MatchesScope(scope, request.ProcessPath);

    internal static bool MatchesScope(string? scope, string? candidate)
    {
        if (string.IsNullOrWhiteSpace(scope) || string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        return LooksLikePath(scope) ? MatchesPath(scope, candidate) : MatchesHost(scope, candidate);
    }

    private static bool LooksLikePath(string scope) =>
        scope.Contains('/', StringComparison.Ordinal)
        || scope.Contains('\\', StringComparison.Ordinal)
        || (scope.Length > 1 && scope[1] == ':');

    private static bool MatchesPath(string scope, string candidate)
    {
        var normalizedScope = NormalizePath(scope);
        var normalizedCandidate = NormalizePath(candidate);

        if (normalizedCandidate.Equals(normalizedScope, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var prefix = normalizedScope.EndsWith('/') ? normalizedScope : normalizedScope + "/";
        return normalizedCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string value)
    {
        var normalized = value.Trim().Trim('"', '\'').Replace('\\', '/');
        if (normalized.StartsWith("file:///", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["file:///".Length..];
        }
        else if (normalized.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "//" + normalized["file://".Length..];
        }

        if (normalized.StartsWith("//?/UNC/", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "//" + normalized["//?/UNC/".Length..];
        }
        else if (normalized.StartsWith("//?/", StringComparison.Ordinal) ||
                 normalized.StartsWith("//./", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        var isUnc = normalized.StartsWith("//", StringComparison.Ordinal);
        var isUnixRoot = !isUnc && normalized.StartsWith('/');
        var parts = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            return isUnixRoot ? "/" : string.Empty;
        }

        var isDriveRoot = !isUnc && !isUnixRoot && parts[0].Length == 2 && parts[0][1] == ':';
        var anchorCount = isDriveRoot ? 1 : 0;
        var resolved = new List<string>(parts.Length);

        foreach (var part in parts)
        {
            if (part == ".")
            {
                continue;
            }

            if (part == "..")
            {
                if (resolved.Count > anchorCount && resolved[^1] != "..")
                {
                    resolved.RemoveAt(resolved.Count - 1);
                }
                else if (!isDriveRoot && !isUnixRoot && !isUnc)
                {
                    resolved.Add(part);
                }

                continue;
            }

            resolved.Add(part);
        }

        var joined = string.Join('/', resolved);
        if (isUnc)
        {
            return "//" + joined;
        }

        return isUnixRoot ? "/" + joined : joined;
    }

    private static bool MatchesHost(string scope, string candidate)
    {
        var host = ExtractHost(candidate);
        if (host.Length == 0)
        {
            return false;
        }

        var expected = scope.Trim().TrimEnd('.');
        if (host.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return host.EndsWith("." + expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string ExtractHost(string candidate)
    {
        if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
        {
            return uri.IdnHost.TrimEnd('.');
        }

        var host = candidate;
        var slash = host.IndexOf('/', StringComparison.Ordinal);
        if (slash > 0)
        {
            host = host[..slash];
        }

        if (!host.Contains('[', StringComparison.Ordinal))
        {
            var colon = host.LastIndexOf(':');
            if (colon > 0)
            {
                host = host[..colon];
            }
        }

        return host.Trim().TrimEnd('.');
    }
}
