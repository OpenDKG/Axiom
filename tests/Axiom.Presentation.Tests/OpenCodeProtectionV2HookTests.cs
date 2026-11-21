// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class OpenCodeProtectionV2HookTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), $"axiom-opencode-v2-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    [Fact]
    public void EnsureInstalled_registers_per_directory_hooks_and_upgrades_stale_v147_plugin()
    {
        Directory.CreateDirectory(Path.Combine(_root, ".config", "opencode"));
        var python = Path.Combine(
            _root,
            "Axiom",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        if (!OperatingSystem.IsWindows())
        {
            python = Path.Combine(
                _root,
                "Axiom",
                "modules",
                "blackbox",
                "agent-blackbox",
                "venv",
                "bin",
                "python");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var protection = new OpenCodeProtection(_root, _root, _root);

        // Simulate a stale 1.4.7 plugin that blocked setup(ctx) across workspaces with __axiomBlackboxHooksInstalled.
        Directory.CreateDirectory(protection.PluginDirectory);
        File.WriteAllText(
            protection.PluginPath,
            "// Managed by Axiom.\nPlugin.define({ setup(ctx) { if (globalThis.__axiomBlackboxHooksInstalled) return; ctx.tool.hook(); } })");
        File.WriteAllText(protection.BridgePath, "# stale bridge");
        Assert.False(protection.IsInstalled);

        Assert.True(protection.EnsureInstalled());
        Assert.True(protection.IsInstalled);

        var v2 = File.ReadAllText(protection.PluginPath);
        var v1 = File.ReadAllText(protection.V1PluginPath);

        Assert.DoesNotContain("__axiomBlackboxHooksInstalled", v2, StringComparison.Ordinal);
        Assert.DoesNotContain("__axiomBlackboxHooksInstalled", v1, StringComparison.Ordinal);
        Assert.Contains("__axiomHookLoadedRecorded", v2, StringComparison.Ordinal);
        Assert.Contains("const registration = await ctx.tool.hook(\"execute.before\"", v2, StringComparison.Ordinal);
        Assert.Contains("return () => registration?.dispose?.()", v2, StringComparison.Ordinal);
        Assert.Contains("const registration = context.tool.hook(\"execute.before\"", v1, StringComparison.Ordinal);
        Assert.Contains("return () => registration?.dispose?.()", v1, StringComparison.Ordinal);
    }

    [Fact]
    public void Findings_and_hook_evidence_expose_exact_local_date_and_time()
    {
        var utc = new DateTimeOffset(2026, 11, 21, 18, 45, 12, TimeSpan.Zero);
        var expected = utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        var finding = new BlackboxFinding(
            utc,
            "secret:private-key",
            "fileaccess",
            "critical",
            "Blocked protected key read",
            "openchamber",
            "sess-1",
            "shell",
            "block",
            "blackbox",
            Confirmed: true);
        var evidence = new AgentEvidenceEvent(
            utc,
            "opencode",
            "GUARD_BLOCKED",
            "shell",
            "block",
            "blocked",
            14,
            string.Empty);

        Assert.Equal(expected, finding.DateTimeText);
        Assert.Equal(expected, evidence.DateTimeText);
    }
}
