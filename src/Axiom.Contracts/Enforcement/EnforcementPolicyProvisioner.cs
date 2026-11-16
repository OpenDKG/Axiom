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
/// The installer writes it elevated; a normal desktop start cannot write ProgramData and simply
/// returns null.
/// </remarks>
public static class EnforcementPolicyProvisioner
{
    public const string FileName = "enforcement-policy.json";

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
        var path = ResolvePath(machineRoot);
        if (File.Exists(path))
        {
            return null;
        }

        var profile = string.IsNullOrWhiteSpace(userProfile)
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : userProfile;

        try
        {
            var directory = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(directory);
            var temporary = path + ".tmp";
            File.WriteAllText(temporary, BuildDefaultPolicy(profile), new UTF8Encoding(false));
            File.Move(temporary, path, overwrite: false);
            return path;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>The JSON envelope the service deserializes (camelCase, enums as camelCase strings).</summary>
    public static string BuildDefaultPolicy(string userProfile)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userProfile);

        var agents = new JsonArray();
        var resources = new JsonArray();
        var scopes = new List<string>(ProtectedScopes.Count);

        for (var index = 0; index < ProtectedScopes.Count; index++)
        {
            var scope = Path.Combine(userProfile, ProtectedScopes[index]);
            scopes.Add(scope);
            resources.Add(new JsonObject
            {
                ["resourceId"] = string.Create(CultureInfo.InvariantCulture, $"protected-{index + 1}"),
                ["scope"] = scope,
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
}
