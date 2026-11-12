// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;

namespace Axiom.Presentation;

/// <summary>Read-only process presence check used as supporting status evidence, never as proof of blocking.</summary>
public static class AgentProcessProbe
{
    private static readonly TimeSpan SnapshotLifetime = TimeSpan.FromSeconds(2);
    private static readonly object Gate = new();
    private static HashSet<string> _runningNames = new(StringComparer.OrdinalIgnoreCase);
    private static DateTimeOffset _snapshotUtc = DateTimeOffset.MinValue;

    public static bool IsRunning(string kind) =>
        kind.ToLowerInvariant() switch
        {
            "claude" => Running("claude"),
            "codex" => Running("codex"),
            "cursor" => Running("cursor"),
            "copilot" => Running("copilot") || Running("gh"),
            "gemini" => Running("gemini"),
            "windsurf" => Running("windsurf"),
            "antigravity" => Running("antigravity"),
            "cline" => Running("cline") || Running("Code"),
            "opencode" => Running("opencode"),
            "openchamber" => Running("openchamber"),
            "hermes" => Running("hermes"),
            "openclaw" => Running("openclaw"),
            _ => false,
        };

    private static bool Running(string name)
    {
        try
        {
            return GetRunningProcessNames().Contains(name);
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static HashSet<string> GetRunningProcessNames()
    {
        var now = DateTimeOffset.UtcNow;
        lock (Gate)
        {
            if (now - _snapshotUtc < SnapshotLifetime)
            {
                return _runningNames;
            }

            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(process.ProcessName))
                    {
                        names.Add(process.ProcessName);
                    }
                }
                catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    // Process may exit while enumerating.
                }
                finally
                {
                    process.Dispose();
                }
            }

            _runningNames = names;
            _snapshotUtc = now;
            return _runningNames;
        }
    }
}
