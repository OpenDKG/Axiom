// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;

namespace Axiom.UI.Services;

/// <summary>
/// Provisions Axiom-managed hooks for every detected harness once per build. It never overwrites
/// user-authored hooks and never grants host-owned trust (Codex still owns its /hooks approval).
/// </summary>
public static class AgentHookMaintenance
{
    public static void ProvisionDetectedHooks()
    {
        var marker = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "hook-maintenance.version");
        var version = typeof(AgentHookMaintenance).Assembly.GetName().Version?.ToString() ?? "unknown";
        try
        {
            var assemblyPath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(assemblyPath) || !File.Exists(assemblyPath))
            {
                assemblyPath = Path.Combine(AppContext.BaseDirectory, "Axiom.UI.dll");
            }

            if (File.Exists(assemblyPath))
            {
                version += ":" + File.GetLastWriteTimeUtc(assemblyPath).Ticks.ToString(CultureInfo.InvariantCulture);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A version-only marker is still better than repairing on every start.
        }

        try
        {
            if (File.Exists(marker) &&
                string.Equals(File.ReadAllText(marker).Trim(), version, StringComparison.Ordinal))
            {
                return;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Missing or unreadable marker means "run the repair once".
        }

        var openCode = new OpenCodeProtection();
        Ensure(() => openCode.EnsureInstalled());

        var codex = new CodexProtection();
        Ensure(() => codex.EnsureInstalled());

        var claude = new ClaudeProtection();
        Ensure(() => claude.EnsureInstalled());

        var cursor = new CursorProtection();
        Ensure(() => cursor.EnsureInstalled());

        var copilot = new CopilotProtection();
        Ensure(() => copilot.EnsureInstalled());

        var gemini = new GeminiProtection();
        Ensure(() => gemini.EnsureInstalled());

        var windsurf = new WindsurfProtection();
        Ensure(() => windsurf.EnsureInstalled());

        var cline = new ClineProtection();
        Ensure(() => cline.EnsureInstalled());

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
            File.WriteAllText(marker, version);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The maintenance pass may run again next start; it is idempotent.
        }
    }

    private static void Ensure(Func<bool> ensureInstalled)
    {
        try
        {
            _ = ensureInstalled();
        }
        catch
        {
            // A provisioning pass must never prevent Axiom from starting.
        }
    }
}
