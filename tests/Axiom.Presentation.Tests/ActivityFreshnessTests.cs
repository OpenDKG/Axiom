// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ActivityFreshnessTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 21, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Recent_event_is_not_stale()
    {
        Assert.False(ActivityFreshness.IsStale(Now.AddMinutes(-2), Now));
    }

    [Fact]
    public void Old_event_is_stale_and_the_text_names_the_time()
    {
        var newest = Now.AddHours(-6);

        Assert.True(ActivityFreshness.IsStale(newest, Now));
        var text = ActivityFreshness.Describe(newest, Now);
        Assert.Contains("No new agent activity", text, StringComparison.Ordinal);
        Assert.Contains("6h 00m", text, StringComparison.Ordinal);
        Assert.Contains("Install/repair agent hooks", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_history_is_reported_without_a_bogus_timestamp()
    {
        Assert.False(ActivityFreshness.IsStale(null, Now));
        Assert.Equal("No recorded agent event yet.", ActivityFreshness.Describe(null, Now));
    }

    [Fact]
    public void Old_event_when_no_agent_is_running_is_idle_not_stale()
    {
        var newest = Now.AddHours(-2);

        Assert.False(ActivityFreshness.IsStale(newest, Now, anyAgentRunning: false));
        var text = ActivityFreshness.Describe(newest, Now, anyAgentRunning: false);
        Assert.Contains("Last agent activity at", text, StringComparison.Ordinal);
        Assert.Contains("no active agent session", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// A temporary directory whose path has no symlinked ancestors. macOS runs its
    /// temp directory under /var, which links to /private/var, and the hook installer
    /// deliberately refuses paths that contain a reparse point.
    /// </summary>
    private static string CreateLinkFreeTempRoot(string prefix)
    {
        var candidate = Path.Combine(Path.GetTempPath(), $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(candidate);
        if (!StorageSafety.IsReparsePointInPath(candidate))
        {
            return candidate;
        }

        Directory.Delete(candidate, recursive: true);
        var fallbackRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".axiom-test-tmp");
        Directory.CreateDirectory(fallbackRoot);
        var fallback = Path.Combine(fallbackRoot, $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(fallback);
        return fallback;
    }

    [Fact]
    public void Antigravity_protection_writes_hooks_without_utf8_bom_and_repairs_existing_bom()
    {
        var root = CreateLinkFreeTempRoot("axiom-agy");
        var userProfile = Path.Combine(root, "user");
        var localAppData = Path.Combine(root, "local");
        try
        {
            Directory.CreateDirectory(Path.Combine(userProfile, ".gemini"));
            var scriptsDir = Path.Combine(localAppData, "Axiom", "modules", "blackbox", "agent-blackbox", "venv", "Scripts");
            Directory.CreateDirectory(scriptsDir);
            File.WriteAllText(Path.Combine(scriptsDir, "python.exe"), "stub");

            var protection = new AntigravityProtection(userProfile, localAppData);
            Assert.True(protection.EnsureInstalled());
            Assert.True(protection.IsInstalled);

            var bytes = File.ReadAllBytes(protection.HooksPath);
            Assert.True(bytes.Length > 3);
            Assert.False(bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);

            var text = File.ReadAllText(protection.HooksPath);
            Assert.DoesNotContain("\\\"", text, StringComparison.Ordinal);

            // Simulate a legacy hooks.json written with a UTF-8 BOM.
            File.WriteAllText(protection.HooksPath, text, Encoding.UTF8);
            Assert.False(protection.IsInstalled);

            Assert.True(protection.EnsureInstalled());
            Assert.True(protection.IsInstalled);
            var repaired = File.ReadAllBytes(protection.HooksPath);
            Assert.False(repaired[0] == 0xEF && repaired[1] == 0xBB && repaired[2] == 0xBF);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void Antigravity_protection_wraps_and_repairs_hook_paths_with_spaces_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateLinkFreeTempRoot("axiom-agy-spaces");
        var userProfile = Path.Combine(root, "Jane (Work) & Co");
        var localAppData = Path.Combine(userProfile, "AppData", "Local");
        try
        {
            Directory.CreateDirectory(Path.Combine(userProfile, ".gemini"));
            var scriptsDir = Path.Combine(localAppData, "Axiom", "modules", "blackbox", "agent-blackbox", "venv", "Scripts");
            Directory.CreateDirectory(scriptsDir);
            var pythonExe = Path.Combine(scriptsDir, "python.exe");
            File.WriteAllText(pythonExe, "stub");

            var protection = new AntigravityProtection(userProfile, localAppData);
            Assert.True(protection.EnsureInstalled());
            Assert.True(protection.IsInstalled);
            Assert.True(File.Exists(protection.HookCmdPath));

            var hooksJson = File.ReadAllText(protection.HooksPath);
            Assert.DoesNotContain("\\\"", hooksJson, StringComparison.Ordinal);

            var rootNode = System.Text.Json.Nodes.JsonNode.Parse(hooksJson)!.AsObject();
            var cmd = rootNode["axiom-guard"]!["PreToolUse"]![0]!["hooks"]![0]!["command"]!.GetValue<string>();
            Assert.DoesNotContain("\"", cmd, StringComparison.Ordinal);
            Assert.Contains("axiom-antigravity-hook.cmd", cmd, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Jane^ ^(Work^)^ ^&^ Co", cmd, StringComparison.Ordinal);

            var cmdBytes = File.ReadAllBytes(protection.HookCmdPath);
            Assert.False(cmdBytes.Length >= 3 && cmdBytes[0] == 0xEF && cmdBytes[1] == 0xBB && cmdBytes[2] == 0xBF);
            var cmdText = File.ReadAllText(protection.HookCmdPath);
            Assert.Contains("\"%~dp0venv\\Scripts\\python.exe\" \"%~dp0axiom-antigravity-hook.py\" %*", cmdText, StringComparison.Ordinal);

            // Simulate a legacy unquoted space-broken hooks.json entry; IsInstalled must report false and repair cleanly.
            rootNode["axiom-guard"]!["PreToolUse"]![0]!["hooks"]![0]!["command"] = $"{pythonExe} {protection.HookScriptPath}";
            File.WriteAllText(protection.HooksPath, rootNode.ToJsonString(), new UTF8Encoding(false));
            Assert.False(protection.IsInstalled);
            Assert.True(protection.EnsureInstalled());
            Assert.True(protection.IsInstalled);

            protection.Remove();
            Assert.False(File.Exists(protection.HookScriptPath));
            Assert.False(File.Exists(protection.HookCmdPath));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void Agent_evidence_store_expands_tail_window_for_records_exceeding_512_bytes()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-evidence-{Guid.NewGuid():N}.jsonl");
        try
        {
            var padding = new string('x', 520);
            var builder = new StringBuilder();
            for (var i = 0; i < 4000; i++)
            {
                var ts = Now.AddSeconds(i).ToString("O");
                var line =
                    "{\"timestampUtc\":\"" + ts +
                    "\",\"framework\":\"codex\",\"eventType\":\"GUARD_ALLOWED\",\"tool\":\"tool-" +
                    i.ToString(System.Globalization.CultureInfo.InvariantCulture) + "-" + padding +
                    "\",\"decision\":\"allowed\",\"guardStatus\":\"allowed\",\"durationMs\":5,\"session\":\"s-" +
                    i.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\",\"call\":\"c-" +
                    i.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\"}";
                builder.AppendLine(line);
            }

            File.WriteAllText(path, builder.ToString(), new UTF8Encoding(false));
            var store = new AgentEvidenceStore(path);

            var firstRead = store.ReadRecent(4000);
            Assert.Equal(4000, firstRead.Count);
            Assert.StartsWith("tool-0-", firstRead[0].Tool, StringComparison.Ordinal);
            Assert.StartsWith("tool-3999-", firstRead[^1].Tool, StringComparison.Ordinal);

            var cachedRead = store.ReadRecent(4000);
            Assert.Equal(4000, cachedRead.Count);
            Assert.StartsWith("tool-0-", cachedRead[0].Tool, StringComparison.Ordinal);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
