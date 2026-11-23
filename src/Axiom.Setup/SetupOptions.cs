// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Setup;

public enum SetupInstallMode
{
    Complete = 0,
    Light = 1,
    Optional = 2,
}

public sealed record SetupOptions(
    string InstallDir,
    bool CreateShortcut,
    bool StartAfterInstall,
    bool CompleteInstallation,
    bool Silent = false,
    bool AcceptRisk = false,
    bool Uninstall = false,
    bool AllowManualThreatSharing = false,
    bool EnableAutomaticThreatSharing = false,
    SetupInstallMode Mode = SetupInstallMode.Complete,
    bool EnableFirewallShield = true,
    bool EnablePrivacyShield = true,
    bool EnableAutostartAndFeed = true,
    bool InstallBlackbox = true,
    bool InstallDkg = true,
    bool InstallAgentHooks = true)
{
    public SetupInstallMode EffectiveMode =>
        Mode == SetupInstallMode.Complete && !CompleteInstallation
            ? SetupInstallMode.Light
            : Mode;

    public bool EffectiveFirewallShield =>
        EffectiveMode == SetupInstallMode.Optional ? EnableFirewallShield : true;

    public bool EffectivePrivacyShield =>
        EffectiveMode == SetupInstallMode.Optional ? EnablePrivacyShield : true;

    public bool EffectiveAutostartAndFeed =>
        EffectiveMode == SetupInstallMode.Optional ? EnableAutostartAndFeed : true;

    public bool EffectiveInstallBlackbox =>
        EffectiveMode == SetupInstallMode.Complete ||
        (EffectiveMode == SetupInstallMode.Optional && InstallBlackbox);

    public bool EffectiveInstallDkg =>
        EffectiveMode == SetupInstallMode.Complete ||
        (EffectiveMode == SetupInstallMode.Optional && InstallDkg);

    public bool EffectiveInstallAgentHooks =>
        EffectiveMode == SetupInstallMode.Complete ||
        (EffectiveMode == SetupInstallMode.Optional && InstallAgentHooks);

    public bool RequiresWindowsService => EffectiveFirewallShield || EffectivePrivacyShield;

    public static SetupOptions Parse(string[] args)
    {
        var installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs",
            "Axiom");

        var createShortcut = true;
        var startAfterInstall = true;
        var mode = SetupInstallMode.Complete;
        var enableFirewallShield = true;
        var enablePrivacyShield = true;
        var enableAutostartAndFeed = true;
        var installBlackbox = true;
        var installDkg = true;
        var installAgentHooks = true;
        var silent = false;
        var acceptRisk = false;
        var uninstall = false;
        var allowManualThreatSharing = false;
        var disableAutomaticThreatSharing = false;

        for (var index = 0; index < args.Length; index++)
        {
            var arg = args[index];
            if (arg.StartsWith("--install-dir=", StringComparison.OrdinalIgnoreCase))
            {
                TrySetInstallDir(arg["--install-dir=".Length..], ref installDir);
                continue;
            }

            switch (arg.ToLowerInvariant())
            {
                case "--install-dir" when index + 1 < args.Length:
                    TrySetInstallDir(args[++index], ref installDir);
                    break;
                case "--no-shortcut":
                    createShortcut = false;
                    break;
                case "--no-launch":
                    startAfterInstall = false;
                    break;
                case "--complete":
                case "--full":
                    mode = SetupInstallMode.Complete;
                    enableFirewallShield = true;
                    enablePrivacyShield = true;
                    enableAutostartAndFeed = true;
                    installBlackbox = true;
                    installDkg = true;
                    installAgentHooks = true;
                    break;
                case "--light":
                case "--no-hooks":
                case "--partial":
                    mode = SetupInstallMode.Light;
                    enableFirewallShield = true;
                    enablePrivacyShield = true;
                    enableAutostartAndFeed = true;
                    installBlackbox = false;
                    installDkg = false;
                    installAgentHooks = false;
                    break;
                case "--optional":
                case "--custom":
                    mode = SetupInstallMode.Optional;
                    enableFirewallShield = true;
                    enablePrivacyShield = true;
                    enableAutostartAndFeed = true;
                    installBlackbox = false;
                    installDkg = false;
                    installAgentHooks = false;
                    break;
                case "--no-firewall":
                    mode = SetupInstallMode.Optional;
                    enableFirewallShield = false;
                    break;
                case "--with-firewall":
                    mode = SetupInstallMode.Optional;
                    enableFirewallShield = true;
                    break;
                case "--no-privacy-shield":
                    mode = SetupInstallMode.Optional;
                    enablePrivacyShield = false;
                    break;
                case "--with-privacy-shield":
                    mode = SetupInstallMode.Optional;
                    enablePrivacyShield = true;
                    break;
                case "--no-autostart":
                    mode = SetupInstallMode.Optional;
                    enableAutostartAndFeed = false;
                    break;
                case "--with-autostart":
                    mode = SetupInstallMode.Optional;
                    enableAutostartAndFeed = true;
                    break;
                case "--no-blackbox":
                    mode = SetupInstallMode.Optional;
                    installBlackbox = false;
                    break;
                case "--with-blackbox":
                    mode = SetupInstallMode.Optional;
                    installBlackbox = true;
                    break;
                case "--no-dkg":
                    mode = SetupInstallMode.Optional;
                    installDkg = false;
                    break;
                case "--with-dkg":
                    mode = SetupInstallMode.Optional;
                    installDkg = true;
                    break;
                case "--no-agent-hooks":
                    mode = SetupInstallMode.Optional;
                    installAgentHooks = false;
                    break;
                case "--with-agent-hooks":
                    mode = SetupInstallMode.Optional;
                    installAgentHooks = true;
                    break;
                case "--silent":
                    silent = true;
                    break;
                case "--accept-risk":
                    acceptRisk = true;
                    break;
                case "--allow-manual-threat-sharing":
                    allowManualThreatSharing = true;
                    break;
                case "--no-automatic-threat-sharing":
                    disableAutomaticThreatSharing = true;
                    break;
                case "--uninstall":
                    uninstall = true;
                    break;
            }
        }

        var completeInstallation = mode == SetupInstallMode.Complete;
        var effectiveInstallBlackbox = mode == SetupInstallMode.Complete ||
                                     (mode == SetupInstallMode.Optional && installBlackbox);

        return new SetupOptions(
            installDir,
            createShortcut,
            startAfterInstall,
            completeInstallation,
            silent,
            acceptRisk,
            uninstall,
            effectiveInstallBlackbox && allowManualThreatSharing,
            effectiveInstallBlackbox && acceptRisk && !disableAutomaticThreatSharing,
            mode,
            enableFirewallShield,
            enablePrivacyShield,
            enableAutostartAndFeed,
            installBlackbox,
            installDkg,
            installAgentHooks);
    }

    private static void TrySetInstallDir(string raw, ref string installDir)
    {
        var trimmed = raw.Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return;
        }

        try
        {
            installDir = Path.GetFullPath(trimmed);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
        }
    }
}
