// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Enforcement;

/// <summary>What to do with a process-creation event seen for an agent session.</summary>
public enum ProcessSpawnVerdict
{
    Allow,
    Record,
    Block,
}

/// <summary>A verdict plus the human-readable reason recorded with it.</summary>
public sealed record ProcessSpawnDecision(ProcessSpawnVerdict Verdict, string Reason);

/// <summary>One process-creation observation (fed later from ETW/WMI by the service).</summary>
public sealed record ProcessSpawnEvent(
    int ProcessId,
    int ParentProcessId,
    string ImagePath,
    string ParentImagePath,
    DateTimeOffset At);

/// <summary>
/// F-19 part B: decides what an agent child process means before the service records or stops it.
/// The policy is pure and testable; the ETW/WMI subscription and the optional termination live in
/// the service layer. A download/staging executable spawned by an agent is blocked; anything else
/// an agent spawns is recorded; unrelated children are ignored.
/// </summary>
public static class AgentProcessSpawnPolicy
{
    private static readonly string[] AgentNames =
    [
        "opencode", "openchamber", "claude", "codex", "hermes", "cursor", "windsurf",
        "gemini", "cline", "copilot", "deepseek", "zcode",
    ];

    private static readonly string[] StagingRoots =
    [
        "\\downloads\\",
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
    ];

    private static readonly string[] RiskyBinaries =
    [
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe",
        "python.exe", "node.exe", "reg.exe", "sc.exe", "schtasks.exe", "wmic.exe",
    ];

    private static readonly string[] ExecutableExtensions =
    [
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com", ".pif",
    ];

    /// <summary>
    /// Evaluates one spawn. <paramref name="allowlist"/> holds exact image paths the operator has
    /// approved; those always pass.
    /// </summary>
    public static ProcessSpawnDecision Evaluate(
        ProcessSpawnEvent spawn,
        IReadOnlyCollection<string>? allowlist = null)
    {
        ArgumentNullException.ThrowIfNull(spawn);

        var image = Normalize(spawn.ImagePath);
        if (image.Length == 0)
        {
            return new ProcessSpawnDecision(ProcessSpawnVerdict.Allow, "no image path");
        }

        if (allowlist is not null)
        {
            foreach (var allowed in allowlist)
            {
                if (string.Equals(Normalize(allowed), image, StringComparison.OrdinalIgnoreCase))
                {
                    return new ProcessSpawnDecision(ProcessSpawnVerdict.Allow, "allowlisted image");
                }
            }
        }

        var parent = Normalize(spawn.ParentImagePath);
        var fromAgent = parent.Length > 0 && IsAgent(parent);
        var staging = IsStaging(image);
        var executable = HasExecutableExtension(image);

        if (fromAgent && staging && executable)
        {
            return new ProcessSpawnDecision(
                ProcessSpawnVerdict.Block,
                "agent spawned an executable from a download or staging folder");
        }

        if (fromAgent)
        {
            return new ProcessSpawnDecision(
                ProcessSpawnVerdict.Record,
                "agent process spawned a child process");
        }

        if (staging && executable)
        {
            return new ProcessSpawnDecision(
                ProcessSpawnVerdict.Record,
                "executable started from a download or staging folder");
        }

        var name = FileName(image);
        if (Array.Exists(RiskyBinaries, binary => string.Equals(binary, name, StringComparison.OrdinalIgnoreCase)))
        {
            return new ProcessSpawnDecision(
                ProcessSpawnVerdict.Record,
                "risky binary started outside an agent session");
        }

        return new ProcessSpawnDecision(ProcessSpawnVerdict.Allow, "not agent-related");
    }

    private static bool IsAgent(string parent)
    {
        var name = FileName(parent);
        foreach (var agent in AgentNames)
        {
            if (name.Contains(agent, StringComparison.OrdinalIgnoreCase) ||
                parent.Contains("\\" + agent + "\\", StringComparison.OrdinalIgnoreCase) ||
                parent.Contains("/" + agent + "/", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsStaging(string image) =>
        Array.Exists(StagingRoots, root => image.Contains(root, StringComparison.OrdinalIgnoreCase));

    private static bool HasExecutableExtension(string image) =>
        Array.Exists(ExecutableExtensions, extension => image.EndsWith(extension, StringComparison.OrdinalIgnoreCase));

    private static string FileName(string path)
    {
        var index = path.LastIndexOfAny(['\\', '/']);
        return index < 0 ? path : path[(index + 1)..];
    }

    private static string Normalize(string? path) => (path ?? string.Empty).Trim().Replace('/', '\\');
}
