// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json.Nodes;

namespace Axiom.Contracts.Enforcement;

/// <summary>
/// Writes the default opt-in enforcement policy the local service reads. Without the file the
/// service reports <c>enforcement.enabled=false</c> and creates no host-deny rules, so a normal
/// install showed a firewall with zero rules and no receipts. The default is deliberately
/// conservative: it blocks agent reads, writes and deletes under the operator's credential stores
/// and answers <c>ask</c> elsewhere. An existing operator policy is never overwritten.
/// </summary>
/// <remarks>
/// The policy lives under <c>%ProgramData%\Axiom</c> because the service runs as LocalSystem:
/// its <c>LocalApplicationData</c> is the system profile, so a per-user file would never be read.
/// A non-elevated caller cannot write ProgramData; the service provisions its own copy at the
/// first status request so an install always ends with a policy.
/// </remarks>
public static class EnforcementPolicyProvisioner
{
    public const string FileName = "enforcement-policy.json";

    /// <summary>Upper bound that keeps <c>agents x scopes</c> under the validator's 512 rules.</summary>
    private const int MaximumScopes = 40;

    /// <summary>Harness identifiers the host adapters report.</summary>
    public static readonly IReadOnlyList<string> AgentIds =
    [
        "claude",
        "codex",
        "cursor",
        "copilot",
        "gemini",
        "windsurf",
        "cline",
        "zcode",
        "antigravity",
        "opencode",
        "deepseek",
    ];

    /// <summary>Relative credential stores every agent is stopped from touching.</summary>
    public static readonly IReadOnlyList<string> ProtectedScopes =
    [
        ".ssh",
        ".aws",
        ".kube",
        ".gnupg",
        ".git-credentials",
        ".npmrc",
        "AppData\\Roaming\\Microsoft\\Credentials",
        "AppData\\Local\\Google\\Chrome\\User Data",
    ];

    public static string ResolvePath(string? machineRoot = null) =>
        Path.Combine(
            string.IsNullOrWhiteSpace(machineRoot)
                ? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
                : machineRoot,
            "Axiom",
            FileName);

    /// <summary>
    /// Writes the default policy when no file exists. Returns the path it wrote, or null when an
    /// operator policy is already present or the write failed (for example without elevation).
    /// </summary>
    public static string? EnsureDefault(string? machineRoot = null, string? userProfile = null)
    {
        // Windows-only defaults: off Windows CommonApplicationData is /usr/share and the profile is
        // the caller's real home, and no OS enforcement reads this policy there. Only explicit
        // roots (tests, tooling) are honoured on other platforms.
        if (!OperatingSystem.IsWindows() &&
            (string.IsNullOrWhiteSpace(machineRoot) || string.IsNullOrWhiteSpace(userProfile)))
        {
            return null;
        }

        var path = ResolvePath(machineRoot);
        var profile = string.IsNullOrWhiteSpace(userProfile)
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : userProfile;
        return EnsureDefaultAt(path, [profile]);
    }

    /// <summary>
    /// Service-side provisioning: covers every local profile that has a credential store or an
    /// Axiom install, because the service cannot know which user made the request. A missing file
    /// is written once; an existing policy is left alone.
    /// </summary>
    public static string? EnsureMachineDefault(string? usersRoot = null, string? policyPath = null)
    {
        // Same rule as EnsureDefault: never enumerate the host's home directories or write a
        // machine path from defaults off Windows.
        if (!OperatingSystem.IsWindows() &&
            (string.IsNullOrWhiteSpace(usersRoot) || string.IsNullOrWhiteSpace(policyPath)))
        {
            return null;
        }

        var path = policyPath ?? ResolvePath();
        var root = usersRoot ?? Path.GetDirectoryName(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        var profiles = DiscoverProfiles(root);
        if (profiles.Count == 0)
        {
            profiles.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        }

        return EnsureDefaultAt(path, profiles);
    }

    private static string? EnsureDefaultAt(string path, IReadOnlyList<string> profiles)
    {
        if (string.IsNullOrWhiteSpace(path) || File.Exists(path))
        {
            return null;
        }

        var candidates = profiles
            .Where(profile => !string.IsNullOrWhiteSpace(profile))
            .Select(Path.TrimEndingDirectorySeparator)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (candidates.Length == 0)
        {
            return null;
        }

        try
        {
            var directory = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(directory);
            var temporary = path + ".tmp";
            File.WriteAllText(temporary, BuildDefaultPolicy(candidates), new UTF8Encoding(false));
            File.Move(temporary, path, overwrite: false);
            return path;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>The JSON envelope the service deserializes (camelCase, enums as camelCase strings).</summary>
    public static string BuildDefaultPolicy(string userProfile) =>
        BuildDefaultPolicy([userProfile]);

    /// <summary>Default policy for one or more user profiles.</summary>
    public static string BuildDefaultPolicy(IReadOnlyList<string> userProfiles)
    {
        ArgumentNullException.ThrowIfNull(userProfiles);

        var scopes = new List<string>();
        foreach (var profile in userProfiles)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(profile);
            foreach (var relative in ProtectedScopes)
            {
                var scope = Path.Combine(profile, relative);
                if (!scopes.Contains(scope, StringComparer.OrdinalIgnoreCase))
                {
                    scopes.Add(scope);
                }
            }
        }

        if (scopes.Count > MaximumScopes)
        {
            scopes.RemoveRange(MaximumScopes, scopes.Count - MaximumScopes);
        }

        var agents = new JsonArray();
        var resources = new JsonArray();

        for (var index = 0; index < scopes.Count; index++)
        {
            resources.Add(new JsonObject
            {
                ["resourceId"] = string.Create(CultureInfo.InvariantCulture, $"protected-{index + 1}"),
                ["scope"] = scopes[index],
                ["kinds"] = new JsonArray("readFile", "writeFile", "deleteFile"),
            });
        }

        foreach (var agent in AgentIds)
        {
            var rules = new JsonArray();
            for (var index = 0; index < scopes.Count; index++)
            {
                rules.Add(new JsonObject
                {
                    ["ruleId"] = string.Create(
                        CultureInfo.InvariantCulture,
                        $"axiom-{agent}-{index + 1}"),
                    ["effect"] = "block",
                    ["targetScope"] = scopes[index],
                });
            }

            agents.Add(new JsonObject
            {
                ["agentId"] = agent,
                ["mode"] = "protectSelectedOperations",
                ["rules"] = rules,
            });
        }

        var policy = new JsonObject
        {
            ["enabled"] = true,
            ["policy"] = new JsonObject
            {
                ["agents"] = agents,
                ["protectedResources"] = resources,
                ["version"] = "1",
            },
        };

        return policy.ToJsonString();
    }

    private static List<string> DiscoverProfiles(string? usersRoot)
    {
        var profiles = new List<string>();
        if (string.IsNullOrWhiteSpace(usersRoot) || !Directory.Exists(usersRoot))
        {
            return profiles;
        }

        try
        {
            foreach (var directory in Directory.EnumerateDirectories(usersRoot).Order(StringComparer.OrdinalIgnoreCase))
            {
                var name = Path.GetFileName(directory);
                if (name.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("All Users", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (Directory.Exists(Path.Combine(directory, ".ssh")) ||
                    Directory.Exists(Path.Combine(directory, "AppData", "Local", "Programs", "Axiom")))
                {
                    profiles.Add(directory);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return profiles;
    }
}
