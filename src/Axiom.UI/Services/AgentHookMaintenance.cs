// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;

namespace Axiom.UI.Services;

/// <summary>
/// Repairs only Axiom-managed hook files that are already installed. It never installs a hook
/// for a harness that has not been opted in, and it never grants host-owned trust.
/// </summary>
public static class AgentHookMaintenance
{
    public static void RepairInstalledHooks()
    {
        var marker = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "hook-maintenance.version");
        var version = typeof(AgentHookMaintenance).Assembly.GetName().Version?.ToString() ?? "unknown";
        try
        {
            var assemblyPath = typeof(AgentHookMaintenance).Assembly.Location;
            if (!string.IsNullOrWhiteSpace(assemblyPath) && File.Exists(assemblyPath))
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
        Repair(() => openCode.IsInstalled, () => openCode.EnsureInstalled());

        var codex = new CodexProtection();
        Repair(() => codex.IsInstalled, () => codex.EnsureInstalled());

        var claude = new ClaudeProtection();
        Repair(() => claude.IsInstalled, () => claude.EnsureInstalled());

        var cursor = new CursorProtection();
        Repair(() => cursor.IsInstalled, () => cursor.EnsureInstalled());

        var copilot = new CopilotProtection();
        Repair(() => copilot.IsInstalled, () => copilot.EnsureInstalled());

        var gemini = new GeminiProtection();
        Repair(() => gemini.IsInstalled, () => gemini.EnsureInstalled());

        var windsurf = new WindsurfProtection();
        Repair(() => windsurf.IsInstalled, () => windsurf.EnsureInstalled());

        var cline = new ClineProtection();
        Repair(() => cline.IsInstalled, () => cline.EnsureInstalled());

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

    private static void Repair(Func<bool> isInstalled, Func<bool> ensureInstalled)
    {
        try
        {
            if (isInstalled())
            {
                _ = ensureInstalled();
            }
        }
        catch
        {
            // A maintenance pass must never prevent Axiom from starting.
        }
    }
}
