// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Netpetra.UI.Services;

public sealed record CommunityFeedSettings(bool Enabled, string Url, string Token);

/// <summary>Stores the optional feed URL and protects the optional token with Windows DPAPI.</summary>
public sealed class CommunityFeedSettingsStore
{
    public const string StarterFeedUrl = "https://raw.githubusercontent.com/a-51-50/Netpetra/main/community/feed.json";

    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "community-feed.json");

    public CommunityFeedSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return new CommunityFeedSettings(false, string.Empty, string.Empty);
            }

            using var document = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            var root = document.RootElement;
            var enabled = root.TryGetProperty("enabled", out var enabledElement) && enabledElement.GetBoolean();
            var url = root.TryGetProperty("url", out var urlElement) ? urlElement.GetString() ?? string.Empty : string.Empty;
            var protectedToken = root.TryGetProperty("tokenProtected", out var tokenElement)
                ? tokenElement.GetString()
                : null;

            var token = string.IsNullOrWhiteSpace(protectedToken)
                ? string.Empty
                : Encoding.UTF8.GetString(ProtectedData.Unprotect(
                    Convert.FromBase64String(protectedToken),
                    optionalEntropy: null,
                    DataProtectionScope.CurrentUser));

            return new CommunityFeedSettings(enabled, url, token);
        }
        catch (Exception exception) when (exception is
            CryptographicException or JsonException or IOException or FormatException or
            InvalidOperationException or UnauthorizedAccessException)
        {
            return new CommunityFeedSettings(false, string.Empty, string.Empty);
        }
    }

    public void Save(CommunityFeedSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var directory = Path.GetDirectoryName(SettingsPath)
            ?? throw new InvalidOperationException("Community feed settings path has no directory.");
        Directory.CreateDirectory(directory);

        var protectedToken = string.IsNullOrWhiteSpace(settings.Token)
            ? string.Empty
            : Convert.ToBase64String(ProtectedData.Protect(
                Encoding.UTF8.GetBytes(settings.Token),
                optionalEntropy: null,
                DataProtectionScope.CurrentUser));

        var json = JsonSerializer.Serialize(new
        {
            enabled = settings.Enabled,
            url = settings.Url,
            tokenProtected = protectedToken,
        });

        File.WriteAllText(SettingsPath, json);
    }
}
