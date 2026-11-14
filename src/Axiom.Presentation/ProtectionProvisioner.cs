// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.Presentation;

/// <summary>Runs one protection check against the installed guard bridge.</summary>
public delegate ProtectionCheckResult ProtectionCheckRunner(ProtectionCheck check);

/// <summary>Outcome of provisioning and proving agent protection.</summary>
public sealed record ProtectionProvisioningResult(
    string ConfigPath,
    bool BlockMode,
    bool RulesPresent,
    IReadOnlyList<ProtectionCheckResult> Checks,
    bool Passed,
    string State,
    string Summary);

/// <summary>
/// Writes block mode where the guard reads it, verifies the effective setting, and runs the
/// self-test. A complete install must not report success without this passing.
/// </summary>
public static class ProtectionProvisioner
{
    private static readonly JsonSerializerOptions StatusJsonOptions = new() { WriteIndented = true };
    /// <summary>
    /// Applies block mode and (optionally) runs the self-test. All file and process access is
    /// injected so the decision logic is testable on any machine.
    /// </summary>
    public static ProtectionProvisioningResult Provision(
        string localAppData,
        string userProfile,
        Func<string, bool> fileExists,
        Func<string, string?> readText,
        Action<string, string> writeText,
        ProtectionCheckRunner? runner,
        bool rulesPresent = false)
    {
        var configPath = HermesConfigLocation.Resolve(localAppData, userProfile, fileExists);
        var existing = readText(configPath) ?? string.Empty;
        var updated = HermesConfigLocation.ApplyMode(existing, "block");
        if (!string.Equals(existing, updated, StringComparison.Ordinal))
        {
            writeText(configPath, updated);
        }

        var blockMode = HermesConfigLocation.IsBlockMode(readText(configPath) ?? string.Empty);

        var results = runner is null
            ? []
            : AgentProtectionSelfTest.DefaultChecks().Select(check => runner(check)).ToArray();

        var checksPassed = results.Length > 0 && AgentProtectionSelfTest.AllPassed(results);
        var passed = blockMode && checksPassed && rulesPresent;
        var state = passed ? "protected" : "unprotected";

        var reasons = new List<string>();
        if (!blockMode)
        {
            reasons.Add("block mode is not active");
        }

        if (!rulesPresent)
        {
            reasons.Add("threat ruleset is empty — sync the verified graph or apply confirmed rules");
        }

        if (results.Length == 0)
        {
            reasons.Add("self-test did not run");
        }
        else if (!checksPassed)
        {
            reasons.Add(AgentProtectionSelfTest.Summary(results));
        }

        var summary = reasons.Count == 0
            ? AgentProtectionSelfTest.Summary(results)
            : "UNPROTECTED: " + string.Join("; ", reasons);

        return new ProtectionProvisioningResult(configPath, blockMode, rulesPresent, results, passed, state, summary);
    }

    /// <summary>
    /// True when the compiled ruleset carries at least one rule or verified-scope counts. An empty
    /// ruleset means detection has nothing to match, so the install must show UNPROTECTED.
    /// </summary>
    public static bool HasVerifiedRules(string? rulesetJson)
    {
        if (string.IsNullOrWhiteSpace(rulesetJson))
        {
            return false;
        }

        try
        {
            var root = JsonNode.Parse(rulesetJson);
            if (root is not JsonObject document)
            {
                return false;
            }

            foreach (var key in new[] { "injection", "skill", "escalation", "fileaccess", "graph_threats" })
            {
                if (document[key] is JsonArray array && array.Count > 0)
                {
                    return true;
                }
            }

            if (document["verified_scope"] is JsonObject scope &&
                scope["verified_counts"] is JsonObject counts &&
                counts.Count > 0)
            {
                return true;
            }

            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Runs at desktop start for the complete profile: write block mode, prove it, persist the
    /// outcome. Returns null for the light profile or when Axiom is not installed in this profile.
    /// </summary>
    public static ProtectionProvisioningResult? ProvisionAtStartup(string? localAppData = null) =>
        ProvisionAtStartup(localAppData, AgentPlatform.IsWindows);

    /// <summary>
    /// <paramref name="windows"/> false: nothing is read, written or started and the result is null.
    /// The provisioning below is the Windows guard runtime (block mode in the Hermes config, the
    /// bridge under <c>venv\Scripts\python.exe</c>); there is no macOS/Linux counterpart yet, so those
    /// hosts stay unprovisioned and report no state (<see cref="BlackboxPlatformSupport"/>).
    /// </summary>
    public static ProtectionProvisioningResult? ProvisionAtStartup(string? localAppData, bool windows)
    {
        if (!windows)
        {
            return null;
        }

        var root = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!IsCompleteProfile(root))
        {
            return null;
        }

        var agentRoot = Path.Combine(root, "Axiom", "modules", "blackbox", "agent-blackbox");
        var runner = CreateBridgeRunner(agentRoot);

        var rulesPresent = false;
        try
        {
            var rulesetPath = Path.Combine(root, "hermes", "blackbox", "ruleset.json");
            if (File.Exists(rulesetPath))
            {
                rulesPresent = HasVerifiedRules(File.ReadAllText(rulesetPath));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            rulesPresent = false;
        }

        var result = Provision(
            root,
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            File.Exists,
            path => File.Exists(path) ? File.ReadAllText(path) : null,
            (path, text) =>
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, text);
            },
            runner,
            rulesPresent);

        try
        {
            var statusPath = Path.Combine(root, "Axiom", "protection-status.json");
            Directory.CreateDirectory(Path.GetDirectoryName(statusPath)!);
            File.WriteAllText(
                statusPath,
                JsonSerializer.Serialize(result, StatusJsonOptions));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Status is evidence, not a prerequisite.
        }

        return result;
    }

    /// <summary>A runner backed by the installed venv Python and the guard bridge, or null.</summary>
    public static ProtectionCheckRunner? CreateBridgeRunner(string agentRoot)
    {
        var python = Path.Combine(agentRoot, "venv", "Scripts", "python.exe");
        var bridge = Path.Combine(agentRoot, "axiom-guard-bridge.py");
        if (!File.Exists(python) || !File.Exists(bridge))
        {
            return null;
        }

        return check => RunBridge(python, bridge, agentRoot, check);
    }

    private static ProtectionCheckResult RunBridge(
        string python,
        string bridge,
        string workingDirectory,
        ProtectionCheck check)
    {
        var payload = AgentProtectionSelfTest.BuildPayload(check, "axiom-self-test");
        try
        {
            var startInfo = new ProcessStartInfo(python, $"\"{bridge}\"")
            {
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new ProtectionCheckResult(check.Name, check.ExpectBlock, false, "process-start-failed");
            }

            process.StandardInput.Write(payload);
            process.StandardInput.Close();
            var stdout = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();
            if (!process.WaitForExit(40_000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return new ProtectionCheckResult(check.Name, check.ExpectBlock, false, "timeout");
            }

            return new ProtectionCheckResult(
                check.Name,
                check.ExpectBlock,
                AgentProtectionSelfTest.IsBlock(stdout),
                AgentProtectionSelfTest.Identifier(stdout));
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new ProtectionCheckResult(check.Name, check.ExpectBlock, false, exception.GetType().Name);
        }
    }

    private static bool IsCompleteProfile(string localAppData)
    {
        try
        {
            var path = Path.Combine(localAppData, "Axiom", "install-profile.json");
            if (!File.Exists(path))
            {
                return false;
            }

            var node = JsonNode.Parse(File.ReadAllText(path));
            return string.Equals(node?["profile"]?.GetValue<string>(), "complete", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or JsonException or InvalidOperationException)
        {
            return false;
        }
    }
}
