// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Setup;

public sealed record SetupOptions(
    string InstallDir,
    bool CreateShortcut,
    bool StartAfterInstall,
    bool CompleteInstallation,
    bool Silent = false,
    bool AcceptRisk = false,
    bool Uninstall = false,
    bool AllowManualThreatSharing = false,
    bool EnableAutomaticThreatSharing = false)
{
    public static SetupOptions Parse(string[] args)
    {
        var installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs",
            "Axiom");

        var createShortcut = true;
        var startAfterInstall = true;
        var completeInstallation = true;
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
                case "--no-hooks":
                case "--partial":
                    completeInstallation = false;
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

        return new SetupOptions(
            installDir,
            createShortcut,
            startAfterInstall,
            completeInstallation,
            silent,
            acceptRisk,
            uninstall,
            completeInstallation && allowManualThreatSharing,
            completeInstallation && acceptRisk && !disableAutomaticThreatSharing);
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
