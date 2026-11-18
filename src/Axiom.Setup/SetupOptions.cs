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
    bool AllowManualThreatSharing = false)
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

        for (var index = 0; index < args.Length; index++)
        {
            switch (args[index].ToLowerInvariant())
            {
                case "--install-dir" when index + 1 < args.Length:
                    installDir = Path.GetFullPath(args[++index]);
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
            completeInstallation && allowManualThreatSharing);
    }
}
