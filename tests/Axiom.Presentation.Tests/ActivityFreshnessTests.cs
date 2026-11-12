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

    [Fact]
    public void Antigravity_protection_writes_hooks_without_utf8_bom_and_repairs_existing_bom()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-agy-{Guid.NewGuid():N}");
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
}
