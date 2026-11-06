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

        var refreshExisting = true;
        try
        {
            refreshExisting = !File.Exists(marker) ||
                              !string.Equals(
                                  File.ReadAllText(marker).Trim(),
                                  version,
                                  StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            refreshExisting = true;
        }

        var openCode = new OpenCodeProtection();
        Ensure(() => openCode.IsInstalled, () => openCode.EnsureInstalled(), refreshExisting);

        var codex = new CodexProtection();
        Ensure(() => codex.IsInstalled, () => codex.EnsureInstalled(), refreshExisting);

        var claude = new ClaudeProtection();
        Ensure(() => claude.IsInstalled, () => claude.EnsureInstalled(), refreshExisting);

        var cursor = new CursorProtection();
        Ensure(() => cursor.IsInstalled, () => cursor.EnsureInstalled(), refreshExisting);

        var copilot = new CopilotProtection();
        Ensure(() => copilot.IsInstalled, () => copilot.EnsureInstalled(), refreshExisting);

        var gemini = new GeminiProtection();
        Ensure(() => gemini.IsInstalled, () => gemini.EnsureInstalled(), refreshExisting);

        var windsurf = new WindsurfProtection();
        Ensure(() => windsurf.IsInstalled, () => windsurf.EnsureInstalled(), refreshExisting);

        var cline = new ClineProtection();
        Ensure(() => cline.IsInstalled, () => cline.EnsureInstalled(), refreshExisting);

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

    private static void Ensure(
        Func<bool> isInstalled,
        Func<bool> ensureInstalled,
        bool refreshExisting)
    {
        try
        {
            if (refreshExisting || !isInstalled())
            {
                _ = ensureInstalled();
            }
        }
        catch
        {
            // A provisioning pass must never prevent Axiom from starting.
        }
    }
}
