// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;

namespace Axiom.Presentation;

/// <summary>Read-only process presence check used as supporting status evidence, never as proof of blocking.</summary>
public static class AgentProcessProbe
{
    public static bool IsRunning(string kind) =>
        kind.ToLowerInvariant() switch
        {
            "claude" => Running("claude"),
            "codex" => Running("codex") || Running("Codex"),
            "cursor" => Running("Cursor") || Running("cursor"),
            "copilot" => Running("copilot") || Running("gh"),
            "gemini" => Running("gemini"),
            "windsurf" => Running("Windsurf") || Running("windsurf"),
            "antigravity" => Running("Antigravity") || Running("antigravity"),
            "cline" => Running("cline") || Running("Code"),
            "opencode" => Running("opencode"),
            "openchamber" => Running("OpenChamber") || Running("openchamber"),
            "hermes" => Running("hermes"),
            "openclaw" => Running("openclaw"),
            _ => false,
        };

    private static bool Running(string name)
    {
        try
        {
            return Process.GetProcessesByName(name).Length > 0;
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
