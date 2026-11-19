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
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "claude.exe")) ||
        MacTools("claude") || MacExists(Home(".claude", "local", "claude"));

    public static bool IsCodexAvailable() =>
        OnPath("codex") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "codex.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "codex", "codex.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "codex.exe")) ||
        MacTools("codex") || MacApp("Codex");

    public static bool IsCursorAvailable() =>
        OnPath("cursor") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "cursor", "Cursor.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Cursor", "Cursor.exe")) ||
        MacTools("cursor") || MacApp("Cursor");

    public static bool IsCopilotAvailable() =>
        OnPath("copilot") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "copilot.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "copilot", "copilot.exe")) ||
        MacTools("copilot");

    public static bool IsGeminiAvailable() =>
        OnPath("gemini") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "gemini.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "gemini", "gemini.exe")) ||
        MacTools("gemini");

    public static bool IsWindsurfAvailable() =>
        OnPath("windsurf") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Windsurf", "Windsurf.exe")) ||
        MacTools("windsurf") || MacApp("Windsurf");

    public static bool IsZCodeAvailable() =>
        OnPath("zcode") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "zcode.cmd"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "zcode", "zcode.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "ZCode", "ZCode.exe")) ||
        MacTools("zcode") || MacApp("ZCode");

    /// <summary>
    /// Detects DeepSeek Harness (<c>dsh</c>). Does not treat <c>deepseek-cli</c> (<c>deepseek</c> on
    /// PATH) as supported because it is a plain chat CLI with no lifecycle hook surface.
    /// </summary>
    public static bool IsDeepSeekAvailable() => IsDeepSeekAvailable(OnPath, File.Exists) || MacTools("dsh");

    internal static bool IsDeepSeekAvailable(
        Func<string, bool> onPath,
        Func<string, bool> exists) =>
        onPath("dsh") ||
        exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "dsh.cmd")) ||
        exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "dsh", "dsh.exe")) ||
        exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", "dsh.exe"));

    public static bool IsClineAvailable()
    {
        if (MacTools("cline") ||
            OnPath("cline") ||
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
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "@opencode-aidesktop", "opencode.exe")) ||
        MacTools("opencode") || MacExists(Home(".opencode", "bin", "opencode")) || MacApp("OpenCode");

    public static bool IsOpenChamberAvailable() =>
        OnPath("openchamber") ||
        Exists(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "@openchamberelectron", "OpenChamber.exe")) ||
        MacTools("openchamber") || MacApp("OpenChamber");

    public static bool IsHermesAvailable() => OnPath("hermes") ||
        MacTools("hermes");

    public static bool IsOpenClawAvailable() => OnPath("openclaw") ||
        MacTools("openclaw");

    private static bool OnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var extensions = AgentPlatform.PathExtensions(
            OperatingSystem.IsWindows(),
            Environment.GetEnvironmentVariable("PATHEXT"));
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

    // macOS: GUI apps inherit launchd's minimal PATH, so Homebrew, npm-global and ~/.local/bin
    // tools are searched explicitly, and desktop agents are found by their .app bundle. These
    // checks are false on every other OS, which keeps Windows detection unchanged.
    private static bool MacTools(string name) =>
        OperatingSystem.IsMacOS() &&
        AgentPlatform.MacExtraSearchDirectories(UserProfile)
            .Any(directory => File.Exists(Path.Combine(directory, name)));

    private static bool MacApp(string bundleName) =>
        OperatingSystem.IsMacOS() &&
        AgentPlatform.MacApplicationDirectories(UserProfile)
            .Any(directory => Directory.Exists(Path.Combine(directory, bundleName + ".app")));

    private static bool MacExists(params string[] paths) => OperatingSystem.IsMacOS() && paths.Any(File.Exists);

    private static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static string Home(params string[] parts) => Path.Combine([UserProfile, .. parts]);
}
