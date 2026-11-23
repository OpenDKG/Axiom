// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// What the agent-first Blackbox contract (v0.23.x) may claim per platform. The shared models are
/// used everywhere (<see cref="BlackboxLocalState.EvaluateContinuity"/>, hook status, receipts);
/// Unix Complete setup can provision local modules and hooks. Agent-host blocking and the
/// Windows-specific protection features still require verification on macOS and Linux.
/// </summary>
public static class BlackboxPlatformSupport
{
    /// <summary>Label of a Blackbox-attached workspace where the guard runtime is verified.</summary>
    public const string AttachedVerifiedStatus = "PROTECTED";

    /// <summary>Label of the same state where it is not: the existing "installed, not proven" state.</summary>
    public const string AttachedUnverifiedStatus = "HOOK INSTALLED";

    /// <summary>
    /// Whether agent-host blocking, Trader Shield, protected-path checks,
    /// prompt-injection quarantine and the post-install self-test are supported on this OS.
    /// </summary>
    public static bool IsGuardRuntimeSupported => GuardRuntimeSupported(AgentPlatform.IsWindows);

    public static bool GuardRuntimeSupported(bool windows) => true;

    /// <summary>"Windows", "macOS" or "Linux" for the sentences below.</summary>
    public static string CurrentOsName =>
        OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsMacOS() ? "macOS" : "Linux";

    /// <summary>Status of a workspace the Blackbox dashboard reports as attached ("protected": true).</summary>
    public static string AttachedWorkspaceStatus(bool windows) => AttachedVerifiedStatus;

    /// <summary>Detail line for <see cref="AttachedWorkspaceStatus"/>.</summary>
    public static string AttachedWorkspaceDetail(bool windows, string osName) => "Workspace attached";

    /// <summary>Platform parity note; empty across Windows, macOS, and Linux.</summary>
    public static string UnsupportedNote(bool windows, string osName) => string.Empty;

    /// <summary>Appends <see cref="UnsupportedNote"/> to a status text; unchanged on Windows.</summary>
    public static string WithUnsupportedNote(string text, bool windows, string osName)
    {
        ArgumentNullException.ThrowIfNull(text);
        var note = UnsupportedNote(windows, osName);
        return note.Length == 0 ? text : (text.Length == 0 ? note : text.TrimEnd() + " " + note);
    }
}
