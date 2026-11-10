// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Platform nouns used in user-facing text. Windows keeps its original wording (Windows Firewall,
/// Windows service, UAC, Named Pipe); macOS names the AxiomFilter network extension, the launchd
/// daemon, the administrator password prompt and the Unix socket instead.
/// </summary>
public static class PlatformText
{
    private static readonly bool Mac = OperatingSystem.IsMacOS();

    /// <summary>"Windows" / "macOS".</summary>
    public static string OsName => Mac ? "macOS" : "Windows";

    /// <summary>The enforcement layer: "Windows Firewall" / "macOS network filter".</summary>
    public static string Firewall => Mac ? "macOS network filter" : "Windows Firewall";

    /// <summary>"Windows service" / "background service (launchd daemon)".</summary>
    public static string ServiceKind => Mac ? "background service (launchd daemon)" : "Windows service";

    /// <summary>Where to look when the service does not start.</summary>
    public static string ServiceCheckHint => Mac
        ? "Check /Library/Logs/Axiom/axiomd.log and 'sudo launchctl print system/com.axiom.service'."
        : "Check Windows Services for 'Axiom'.";

    /// <summary>"UAC" / "administrator password".</summary>
    public static string ElevationName => Mac ? "administrator password" : "UAC";

    /// <summary>"Windows elevation" / "the macOS administrator prompt".</summary>
    public static string ElevationPrompt => Mac ? "the macOS administrator prompt" : "Windows elevation";

    /// <summary>"Windows host" / "Mac".</summary>
    public static string HostKind => Mac ? "Mac" : "Windows host";

    /// <summary>IPC transport name: "Named Pipe" / "Unix socket".</summary>
    public static string IpcTransport => Mac ? "Unix socket" : "Named Pipe";

    /// <summary>Secret store for API keys: "Windows DPAPI" / "the macOS Keychain".</summary>
    public static string SecretStore => Mac ? "the macOS Keychain" : "Windows DPAPI";

    /// <summary>Short form for placeholders: "DPAPI" / "Keychain".</summary>
    public static string SecretStoreShort => Mac ? "Keychain" : "DPAPI";

    public static string ApiKeyPlaceholder => $"stored with {SecretStoreShort}";

    public static string StartWithOs => Mac ? "Open at login" : "Start with Windows";

    public static string StartupScopeNote => Mac
        ? "Only a per-user LaunchAgent (~/Library/LaunchAgents) is written. No machine-wide entry is created."
        : "Only the per-user Axiom startup value is written. No machine-wide entry is created.";

    public static string HideConsoleWindowsLabel => Mac
        ? "Hide background helper windows (Node, Python)"
        : "Hide background console windows (Node, PowerShell, Python)";

    public static string FirewallRulesTitle => Firewall + " · Axiom-owned rules";

    public static string AdapterDnsTitle => $"Adapter DNS (explicit {ElevationName} helper)";

    public static string AskQueueExplanation =>
        "Axiom Shield lists every executable that opened a new outbound connection and has no Block/Allow decision yet. " +
        "It stays listed after the connection ends until you choose Block, Allow or Dismiss. Dismiss hides it until the " +
        "application opens a new connection. This is not a malware verdict, a VirusTotal result or a community-feed match. " +
        $"Block creates an outbound {Firewall} rule for this executable; Allow records an allow decision and removes any existing Axiom block.";
}
