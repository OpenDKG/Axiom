// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Community;

namespace Axiom.Presentation;

/// <summary>Headless commands used by the Unix installer, before the desktop single-instance check.</summary>
public static class UnixAgentSetup
{
    private static readonly JsonSerializerOptions ProfileJsonOptions = new() { WriteIndented = true };
    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static bool TryHandle(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length == 0 || args[0] != "--axiom-unix-agent-setup")
        {
            return false;
        }

        var localData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolderOption.DoNotVerify);
        var runtime = Path.Combine(localData, "Axiom", "modules", "blackbox", "agent-blackbox");
        if (!Path.IsPathFullyQualified(runtime) || StorageSafety.IsReparsePointInPath(runtime))
        {
            Console.Error.WriteLine("Axiom agent setup requires a local application data directory without symbolic links.");
            exitCode = 1;
            return true;
        }

        if (args is [_, "path"])
        {
            Console.WriteLine(runtime);
        }
        else if (args is [_, "refresh"] && AgentPlatform.HasVenvPython(runtime))
        {
            AgentHookMaintenance.ProvisionDetectedHooks();
        }
        else if (args is [_, "profile", var rawProfile])
        {
            var profile = rawProfile.Trim().ToLowerInvariant() switch
            {
                "complete" => "complete",
                "optional" => "optional",
                _ => "light",
            };
            WriteUnixProfile(localData, profile);
        }
        else
        {
            Console.Error.WriteLine("Axiom agent setup requires a working Axiom-managed Blackbox runtime to refresh hooks.");
            exitCode = 1;
        }

        return true;
    }

    private static void WriteUnixProfile(string localData, string profile)
    {
        var dir = Path.Combine(localData, "Axiom");
        Directory.CreateDirectory(dir);
        var hasBlackbox = profile == "complete";
        File.WriteAllText(
            Path.Combine(dir, "install-profile.json"),
            JsonSerializer.Serialize(
                new Dictionary<string, object?>
                {
                    ["profile"] = profile,
                    ["platform"] = OperatingSystem.IsMacOS() ? "macos" : OperatingSystem.IsLinux() ? "linux" : "unix",
                    ["appliedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    ["blackboxInstalled"] = hasBlackbox,
                    ["dkgInstalled"] = hasBlackbox,
                },
                ProfileJsonOptions),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        if (profile is "complete" or "light")
        {
            File.WriteAllText(Path.Combine(dir, "notifications.txt"), "enabled");
            File.WriteAllText(Path.Combine(dir, "tray-notifications.txt"), "enabled");
            var feedPath = Path.Combine(dir, "community-feed.json");
            if (!File.Exists(feedPath))
            {
                File.WriteAllText(
                    feedPath,
                    JsonSerializer.Serialize(
                        new
                        {
                            enabled = true,
                            url = CommunityFeedCatalog.RecommendedBundleUrl,
                            autoSync = true,
                            tokenProtected = string.Empty,
                        },
                        WebJsonOptions),
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
        }

        if (!OnboardingStore.IsCompleted)
        {
            OnboardingStore.Save(new OnboardingSettings(
                Completed: true,
                Skipped: true,
                Dkg: hasBlackbox,
                Blackbox: hasBlackbox));
        }
    }
}
