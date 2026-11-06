// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Axiom.UI.Services;

public sealed record ReputationSettings(bool Enabled, string ApiKey);

/// <summary>
/// Stores the optional VirusTotal key with Windows DPAPI for the current user. The key is never
/// written in plaintext and is never logged.
/// </summary>
public sealed class ReputationSettingsStore
{
    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "reputation.json");

    public ReputationSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return new ReputationSettings(false, string.Empty);
            }

            using var document = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            var root = document.RootElement;
            var enabled = root.TryGetProperty("enabled", out var enabledElement) && enabledElement.GetBoolean();
            var protectedKey = root.TryGetProperty("apiKeyProtected", out var keyElement)
                ? keyElement.GetString()
                : null;

            if (string.IsNullOrWhiteSpace(protectedKey))
            {
                return new ReputationSettings(false, string.Empty);
            }

            var bytes = ProtectedData.Unprotect(
                Convert.FromBase64String(protectedKey),
                optionalEntropy: null,
                DataProtectionScope.CurrentUser);

            return new ReputationSettings(enabled, Encoding.UTF8.GetString(bytes));
        }
        catch (Exception exception) when (exception is
            CryptographicException or JsonException or IOException or FormatException or
            InvalidOperationException or UnauthorizedAccessException)
        {
            return new ReputationSettings(false, string.Empty);
        }
    }

    public void Save(ReputationSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var directory = Path.GetDirectoryName(SettingsPath)
            ?? throw new InvalidOperationException("Reputation settings path has no directory.");
        Directory.CreateDirectory(directory);

        var protectedKey = string.IsNullOrWhiteSpace(settings.ApiKey)
            ? string.Empty
            : Convert.ToBase64String(ProtectedData.Protect(
                Encoding.UTF8.GetBytes(settings.ApiKey),
                optionalEntropy: null,
                DataProtectionScope.CurrentUser));

        var json = JsonSerializer.Serialize(new
        {
            enabled = settings.Enabled,
            apiKeyProtected = protectedKey,
        });

        File.WriteAllText(SettingsPath, json);
    }
}
