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
    bool InstallAgentHooks = true,
    bool RemoveData = false,
    bool AllowDowngrade = false,
    string? ParseError = null)
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
        var hasExplicitMode = false;
        var hasComponentOverride = false;
        var enableFirewallShield = true;
        var enablePrivacyShield = true;
        var enableAutostartAndFeed = true;
        var installBlackbox = true;
        var installDkg = true;
        var installAgentHooks = true;
        var silent = false;
        var acceptRisk = false;
        var uninstall = false;
        var removeData = false;
        var allowDowngrade = false;
        var allowManualThreatSharing = false;
        var enableAutomaticThreatSharing = false;
        var disableAutomaticThreatSharing = false;
        string? parseError = null;

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
                    if (hasExplicitMode && mode != SetupInstallMode.Complete)
                    {
                        parseError ??= $"Conflicting install mode flags: cannot combine '{arg}' with '{mode}' mode.";
                        break;
                    }
                    if (hasComponentOverride)
                    {
                        parseError ??= $"Conflicting flags: '{arg}' cannot be passed after component-level --with/--no flags.";
                        break;
                    }
                    hasExplicitMode = true;
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
                    if (hasExplicitMode && mode != SetupInstallMode.Light)
                    {
                        parseError ??= $"Conflicting install mode flags: cannot combine '{arg}' with '{mode}' mode.";
                        break;
                    }
                    if (hasComponentOverride)
                    {
                        parseError ??= $"Conflicting flags: '{arg}' cannot be passed after component-level --with/--no flags.";
                        break;
                    }
                    hasExplicitMode = true;
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
                    if (hasExplicitMode && mode != SetupInstallMode.Optional)
                    {
                        parseError ??= $"Conflicting install mode flags: cannot combine '{arg}' with '{mode}' mode.";
                        break;
                    }
                    hasExplicitMode = true;
                    mode = SetupInstallMode.Optional;
                    if (!hasComponentOverride)
                    {
                        enableFirewallShield = true;
                        enablePrivacyShield = true;
                        enableAutostartAndFeed = true;
                        installBlackbox = false;
                        installDkg = false;
                        installAgentHooks = false;
                    }
                    break;
                case "--no-firewall":
                case "--with-firewall":
                case "--no-privacy-shield":
                case "--with-privacy-shield":
                case "--no-autostart":
                case "--with-autostart":
                case "--no-blackbox":
                case "--with-blackbox":
                case "--no-dkg":
                case "--with-dkg":
                case "--no-agent-hooks":
                case "--with-agent-hooks":
                    if (hasExplicitMode && mode != SetupInstallMode.Optional)
                    {
                        parseError ??= $"Conflicting flags: '{arg}' cannot be combined with explicit '--{mode.ToString().ToLowerInvariant()}' mode; use '--optional'.";
                        break;
                    }
                    hasComponentOverride = true;
                    mode = SetupInstallMode.Optional;
                    switch (arg.ToLowerInvariant())
                    {
                        case "--no-firewall": enableFirewallShield = false; break;
                        case "--with-firewall": enableFirewallShield = true; break;
                        case "--no-privacy-shield": enablePrivacyShield = false; break;
                        case "--with-privacy-shield": enablePrivacyShield = true; break;
                        case "--no-autostart": enableAutostartAndFeed = false; break;
                        case "--with-autostart": enableAutostartAndFeed = true; break;
                        case "--no-blackbox": installBlackbox = false; break;
                        case "--with-blackbox": installBlackbox = true; break;
                        case "--no-dkg": installDkg = false; break;
                        case "--with-dkg": installDkg = true; break;
                        case "--no-agent-hooks": installAgentHooks = false; break;
                        case "--with-agent-hooks": installAgentHooks = true; break;
                    }
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
                case "--enable-automatic-threat-sharing":
                    enableAutomaticThreatSharing = true;
                    break;
                case "--no-automatic-threat-sharing":
                    disableAutomaticThreatSharing = true;
                    break;
                case "--uninstall":
                    uninstall = true;
                    break;
                case "--remove-data":
                case "--purge-data":
                    removeData = true;
                    break;
                case "--keep-data":
                    removeData = false;
                    break;
                case "--allow-downgrade":
                    allowDowngrade = true;
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
            effectiveInstallBlackbox && enableAutomaticThreatSharing && !disableAutomaticThreatSharing,
            mode,
            enableFirewallShield,
            enablePrivacyShield,
            enableAutostartAndFeed,
            installBlackbox,
            installDkg,
            installAgentHooks,
            removeData,
            allowDowngrade,
            parseError);
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
