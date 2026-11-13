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
    IReadOnlyList<ProtectionCheckResult> Checks,
    bool Passed,
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
        ProtectionCheckRunner? runner)
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

        var passed = blockMode && results.Length > 0 && AgentProtectionSelfTest.AllPassed(results);
        var summary = blockMode
            ? AgentProtectionSelfTest.Summary(results)
            : "block mode is not active" + (results.Length == 0 ? string.Empty : "; " + AgentProtectionSelfTest.Summary(results));

        return new ProtectionProvisioningResult(configPath, blockMode, results, passed, summary);
    }

    /// <summary>
    /// Runs at desktop start for the complete profile: write block mode, prove it, persist the
    /// outcome. Returns null for the light profile or when Axiom is not installed in this profile.
    /// </summary>
    public static ProtectionProvisioningResult? ProvisionAtStartup(string? localAppData = null)
    {
        var root = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!IsCompleteProfile(root))
        {
            return null;
        }

        var agentRoot = Path.Combine(root, "Axiom", "modules", "blackbox", "agent-blackbox");
        var runner = CreateBridgeRunner(agentRoot);

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
            runner);

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
