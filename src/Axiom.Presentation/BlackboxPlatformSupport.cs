// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// What the agent-first Blackbox contract (v0.23.x) may claim per platform. The shared models are
/// used everywhere (<see cref="BlackboxLocalState.EvaluateContinuity"/>, hook status, receipts);
/// the guard runtime with its provisioning exists and is verified on Windows only. On macOS and
/// Linux nothing is provisioned, and a state that only says "a hook is installed" or "a workspace
/// is attached" is never presented as protected.
/// </summary>
public static class BlackboxPlatformSupport
{
    /// <summary>Label of a Blackbox-attached workspace where the guard runtime is verified.</summary>
    public const string AttachedVerifiedStatus = "PROTECTED";

    /// <summary>Label of the same state where it is not: the existing "installed, not proven" state.</summary>
    public const string AttachedUnverifiedStatus = "HOOK INSTALLED";

    /// <summary>
    /// Whether the guard runtime, full-install provisioning, Trader Shield, protected-path checks,
    /// prompt-injection quarantine and the post-install self-test are supported on this OS.
    /// </summary>
    public static bool IsGuardRuntimeSupported => GuardRuntimeSupported(AgentPlatform.IsWindows);

    public static bool GuardRuntimeSupported(bool windows) => windows;

    /// <summary>"Windows", "macOS" or "Linux" for the sentences below.</summary>
    public static string CurrentOsName =>
        OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsMacOS() ? "macOS" : "Linux";

    /// <summary>Status of a workspace the Blackbox dashboard reports as attached ("protected": true).</summary>
    public static string AttachedWorkspaceStatus(bool windows) =>
        windows ? AttachedVerifiedStatus : AttachedUnverifiedStatus;

    /// <summary>Detail line for <see cref="AttachedWorkspaceStatus"/>; Windows keeps upstream's text.</summary>
    public static string AttachedWorkspaceDetail(bool windows, string osName) =>
        windows
            ? "Workspace attached"
            : $"Workspace attached; the Blackbox guard runtime is not verified on {osName}, so it is not shown as protected";

    /// <summary>Empty on Windows; elsewhere the sentence the agent status must carry.</summary>
    public static string UnsupportedNote(bool windows, string osName) =>
        windows
            ? string.Empty
            : $"On {osName} the Blackbox guard runtime, full-install provisioning, Trader Shield, " +
              "protected-path checks, prompt-injection quarantine and the post-install self-test are " +
              "unsupported and unverified; a hooked or attached workspace is not protection.";

    /// <summary>Appends <see cref="UnsupportedNote"/> to a status text; unchanged on Windows.</summary>
    public static string WithUnsupportedNote(string text, bool windows, string osName)
    {
        ArgumentNullException.ThrowIfNull(text);
        var note = UnsupportedNote(windows, osName);
        return note.Length == 0 ? text : (text.Length == 0 ? note : text.TrimEnd() + " " + note);
    }
}
