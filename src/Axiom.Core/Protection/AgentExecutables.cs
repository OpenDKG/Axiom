// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Protection;

/// <summary>
/// Executables that host local coding agents. The list is intentionally narrow: it decides which
/// pending connections are surfaced first and which paths the agent lockdown can cover.
/// </summary>
public static class AgentExecutables
{
    private static readonly string[] Names =
    [
        "opencode",
        "codex",
        "claude",
        "cursor",
        "copilot",
        "gemini",
        "aider",
        "cline",
        "windsurf",
        "zcode",
        "dsh",
        "deepseek",
        "qwen",
        "continue",
        "hermes",
        "goose",
        "antigravity",
    ];

    private static readonly string[] PathHints =
    [
        "\\opencode-cli\\",
        "\\openchamber\\",
        "\\.codex\\",
        "\\.claude\\",
        "\\agent-blackbox\\",
    ];

    public static bool IsAgentPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        // Windows paths reach this on Linux too (shared history/UI); Path.GetFileName does not
        // split backslashes off Windows, so take the last segment under either separator.
        var trimmed = path.TrimEnd('\\', '/');
        var separator = trimmed.LastIndexOfAny(['\\', '/']);
        var file = separator >= 0 ? trimmed[(separator + 1)..] : trimmed;
        var name = System.IO.Path.GetFileNameWithoutExtension(file);
        if (name.Length > 0 &&
            Names.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        return PathHints.Any(hint => path.Contains(hint, StringComparison.OrdinalIgnoreCase));
    }
}
