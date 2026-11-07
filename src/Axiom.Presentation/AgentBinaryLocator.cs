// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Presentation;

/// <summary>
/// Finds agent executables even before the host has created its config directory. Detection is
/// read-only and PATH-based; Axiom never launches the discovered binary.
/// </summary>
public static class AgentBinaryLocator
{
    public static bool IsClaudeAvailable() =>
        OnPath("claude") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "claude.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "claude", "claude.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "claude.exe"));

    public static bool IsCodexAvailable() =>
        OnPath("codex") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "codex.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "codex", "codex.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "codex.exe"));

    public static bool IsCursorAvailable() =>
        OnPath("cursor") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "cursor", "Cursor.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Cursor", "Cursor.exe"));

    public static bool IsCopilotAvailable() =>
        OnPath("copilot") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "copilot.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "copilot", "copilot.exe"));

    public static bool IsGeminiAvailable() =>
        OnPath("gemini") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "gemini.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "gemini", "gemini.exe"));

    public static bool IsWindsurfAvailable() =>
        OnPath("windsurf") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Windsurf", "Windsurf.exe"));

    public static bool IsZCodeAvailable() =>
        OnPath("zcode") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "zcode.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "zcode", "zcode.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "ZCode", "ZCode.exe"));

    public static bool IsDeepSeekAvailable() =>
        OnPath("dsh") ||
        OnPath("deepseek") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "dsh.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "dsh", "dsh.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "dsh.exe"));

    public static bool IsClineAvailable()
    {
        if (OnPath("cline") ||
            Exists(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "cline.cmd"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "cline", "cline.exe")))
        {
            return true;
        }

        var extensions = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".vscode",
            "extensions");
        try
        {
            return Directory.Exists(extensions) &&
                   Directory.EnumerateDirectories(extensions, "saoudrizwan.claude-dev-*").Any();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static bool IsOpenCodeAvailable() =>
        OnPath("opencode") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "opencode", "opencode.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "@opencode-aidesktop", "opencode.exe"));

    public static bool IsOpenChamberAvailable() =>
        OnPath("openchamber") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "@openchamberelectron", "OpenChamber.exe"));

    public static bool IsHermesAvailable() => OnPath("hermes");

    public static bool IsOpenClawAvailable() => OnPath("openclaw");

    private static bool OnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD;.BAT;.COM")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var clean = directory.Trim('"');
            if (clean.Length == 0)
            {
                continue;
            }

            if (File.Exists(Path.Combine(clean, name)))
            {
                return true;
            }

            foreach (var extension in extensions)
            {
                if (File.Exists(Path.Combine(clean, name + extension)))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool Exists(params string[] paths) => paths.Any(File.Exists);
}
