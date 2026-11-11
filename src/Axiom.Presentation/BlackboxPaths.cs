// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Presentation;

/// <summary>
/// One place for the Hermes and Blackbox profile locations. Hermes on Windows uses
/// <c>%LOCALAPPDATA%\hermes</c>, older profiles used <c>~\.hermes</c>, and the official installer
/// also honours <c>HERMES_HOME</c>/<c>BLACKBOX_HOME</c>. The reporter, consent check, mode store
/// and uninstaller must agree, otherwise the reporter runs against a profile with no key.
/// </summary>
public static class BlackboxPaths
{
    public const string HermesHomeVariable = "HERMES_HOME";

    public const string BlackboxHomeVariable = "BLACKBOX_HOME";

    public static string ResolveHermesHome(
        string? userProfile = null,
        string? localAppData = null,
        string? environmentHome = null)
    {
        var configured = environmentHome ?? Environment.GetEnvironmentVariable(HermesHomeVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Normalize(configured);
        }

        var profile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var localCandidate = Path.Combine(local, "hermes");
        if (LooksLikeHermesHome(localCandidate))
        {
            return localCandidate;
        }

        var profileCandidate = Path.Combine(profile, ".hermes");
        if (LooksLikeHermesHome(profileCandidate))
        {
            return profileCandidate;
        }

        // Hermes setup on Windows creates %LOCALAPPDATA%\hermes even when it is still empty.
        return localCandidate;
    }

    public static string ResolveBlackboxHome(
        string? userProfile = null,
        string? localAppData = null,
        string? environmentHome = null,
        string? environmentBlackboxHome = null)
    {
        var configured = environmentBlackboxHome ?? Environment.GetEnvironmentVariable(BlackboxHomeVariable);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Normalize(configured);
        }

        return Path.Combine(
            ResolveHermesHome(userProfile, localAppData, environmentHome),
            "blackbox");
    }

    public static string ConsentPath(
        string? userProfile = null,
        string? localAppData = null,
        string? environmentHome = null,
        string? environmentBlackboxHome = null) =>
        Path.Combine(
            ResolveBlackboxHome(userProfile, localAppData, environmentHome, environmentBlackboxHome),
            "sharing_consent.json");

    public static string ReporterKeyPath(
        string? userProfile = null,
        string? localAppData = null,
        string? environmentHome = null,
        string? environmentBlackboxHome = null) =>
        Path.Combine(
            ResolveBlackboxHome(userProfile, localAppData, environmentHome, environmentBlackboxHome),
            "reporter_key.pem");

    public static bool LooksLikeHermesHome(string path)
    {
        try
        {
            return Directory.Exists(path) &&
                   (File.Exists(Path.Combine(path, "config.yaml")) ||
                    Directory.Exists(Path.Combine(path, "bin")) ||
                    Directory.Exists(Path.Combine(path, "blackbox")));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string Normalize(string path) => path.Trim().Trim('"');
}
