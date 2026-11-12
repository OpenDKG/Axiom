// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Platform nouns used in user-facing text. Windows keeps its original wording (Windows Firewall,
/// Windows service, UAC, Named Pipe); macOS names the AxiomFilter network extension, the launchd
/// daemon, the administrator password prompt and the Unix socket instead; Linux names nftables, the
/// systemd unit, polkit and systemd-resolved.
/// </summary>
public static class PlatformText
{
    private static readonly bool Mac = OperatingSystem.IsMacOS();
    private static readonly bool Linux = OperatingSystem.IsLinux();

    /// <summary>True where the root daemon switches system DNS itself (macOS, Linux).</summary>
    public static bool DaemonSwitchesDns => Mac || Linux;

    /// <summary>"Windows" / "macOS".</summary>
    public static string OsName => Mac ? "macOS" : Linux ? "Linux" : "Windows";

    /// <summary>The enforcement layer: "Windows Firewall" / "macOS network filter".</summary>
    public static string Firewall => Mac ? "macOS network filter" : Linux ? "nftables firewall" : "Windows Firewall";

    /// <summary>"Windows service" / "background service (launchd daemon)".</summary>
    public static string ServiceKind => Mac ? "background service (launchd daemon)" : Linux ? "background service (systemd daemon)" : "Windows service";

    /// <summary>Where to look when the service does not start.</summary>
    public static string ServiceCheckHint => Mac
        ? "Check /Library/Logs/Axiom/axiomd.log and 'sudo launchctl print system/com.axiom.service'."
        : Linux
            ? "Check 'systemctl status axiomd' and 'journalctl -u axiomd'."
            : "Check Windows Services for 'Axiom'.";

    /// <summary>"UAC" / "administrator password".</summary>
    public static string ElevationName => Mac || Linux ? "administrator password" : "UAC";

    /// <summary>"Windows elevation" / "the macOS administrator prompt".</summary>
    public static string ElevationPrompt => Mac ? "the macOS administrator prompt" : Linux ? "the polkit authentication prompt" : "Windows elevation";

    /// <summary>"Windows host" / "Mac".</summary>
    public static string HostKind => Mac ? "Mac" : Linux ? "Linux host" : "Windows host";

    /// <summary>IPC transport name: "Named Pipe" / "Unix socket".</summary>
    public static string IpcTransport => Mac || Linux ? "Unix socket" : "Named Pipe";

    /// <summary>Secret store for API keys: "Windows DPAPI" / "the macOS Keychain".</summary>
    public static string SecretStore => Mac ? "the macOS Keychain" : Linux ? "the Secret Service keyring (file fallback under ~/.local/state/axiom)" : "Windows DPAPI";

    /// <summary>Short form for placeholders: "DPAPI" / "Keychain".</summary>
    public static string SecretStoreShort => Mac ? "Keychain" : Linux ? "keyring" : "DPAPI";

    public static string ApiKeyPlaceholder => $"stored with {SecretStoreShort}";

    public static string StartWithOs => Mac ? "Open at login" : Linux ? "Start at login" : "Start with Windows";

    public static string StartupScopeNote => Mac
        ? "Only a per-user LaunchAgent (~/Library/LaunchAgents) is written. No machine-wide entry is created."
        : Linux
            ? "Only ~/.config/autostart/com.axiom.firewall.desktop is written. No machine-wide entry is created."
            : "Only the per-user Axiom startup value is written. No machine-wide entry is created.";

    public static string HideConsoleWindowsLabel => Mac || Linux
        ? "Hide background helper windows (Node, Python)"
        : "Hide background console windows (Node, PowerShell, Python)";

    public static string FirewallRulesTitle => Firewall + " · Axiom-owned rules";

    /// <summary>The system resolver the daemon reconfigures: "systemd-resolved" / "networksetup".</summary>
    public static string DnsResolverName => Linux ? "systemd-resolved" : Mac ? "networksetup" : "the adapter DNS settings";

    /// <summary>Shown instead of the Windows adapter-DNS helper where the daemon switches DNS itself.</summary>
    public static string DaemonDnsNote => Mac
        ? "On macOS the Axiom daemon switches system DNS to Privacy Shield automatically while the resolver " +
          "runs and restores the previous DNS servers when it stops. No manual change is needed."
        : "On Linux the Axiom daemon points systemd-resolved (per link) at Privacy Shield automatically while the " +
          "resolver runs and restores the previous DNS servers when it stops. No manual change is needed.";

    public static string AdapterDnsTitle => Mac
        ? "System DNS (switched by the Axiom daemon)"
        : Linux
        ? "System DNS (systemd-resolved, switched by the Axiom daemon)"
        : $"Adapter DNS (explicit {ElevationName} helper)";

    public static string AskQueueExplanation =>
        "Axiom Shield lists every executable that opened a new outbound connection and has no Block/Allow decision yet. " +
        "It stays listed after the connection ends until you choose Block, Allow or Dismiss. Dismiss hides it until the " +
        "application opens a new connection. This is not a malware verdict, a VirusTotal result or a community-feed match. " +
        $"Block creates an outbound {Firewall} rule for this executable; Allow records an allow decision and removes any existing Axiom block.";
}
