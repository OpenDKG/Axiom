// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Privacy;

namespace Axiom.Presentation;

/// <summary>
/// Applies the maximum-protection privacy preset for a complete install: Strict profile, every
/// category, every pinned public blocklist source, and the starter community feed. The settings are
/// written per user and pushed to the running service; community sharing stays off.
/// </summary>
public static class PrivacyShieldProvisioner
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    /// <summary>The settings a complete install uses.</summary>
    public static PrivacyShieldSettings CompleteProfileSettings() => new()
    {
        Enabled = true,
        Profile = PrivacyShieldProfile.Strict,
        Categories = PrivacyShieldCategories.ForProfile(PrivacyShieldProfile.Strict)
                     | PrivacyCategory.Custom,
        Port = 53,
        EnabledSourceIds = PrivacyShieldSourceCatalog.All.Select(source => source.Id).ToArray(),
        LogQueries = false,
    };

    /// <summary>Writes <c>privacy-shield.json</c> and <c>community-feed.json</c>.</summary>
    public static void WriteSettings(string localAppData)
    {
        var root = Path.Combine(localAppData, "Axiom");
        Directory.CreateDirectory(root);

        File.WriteAllText(
            Path.Combine(root, "privacy-shield.json"),
            JsonSerializer.Serialize(CompleteProfileSettings(), JsonOptions));

        File.WriteAllText(
            Path.Combine(root, "community-feed.json"),
            JsonSerializer.Serialize(
                new { enabled = true, url = "axiom://starter", tokenProtected = string.Empty },
                JsonOptions));
    }

    /// <summary>
    /// Pushes the preset to the service and asks it to download the blocklists. Best effort: a
    /// stopped service must not fail provisioning, the files remain for the next start.
    /// </summary>
    public static async Task<bool> ApplyAsync(CancellationToken cancellationToken)
    {
        try
        {
            var client = new IpcPipeClient();
            await client.SendAsync<PrivacyShieldStatus>(
                IpcCommandTypes.PrivacyConfigure,
                CompleteProfileSettings(),
                cancellationToken).ConfigureAwait(false);
            await client.SendAsync<PrivacyShieldStatus>(
                IpcCommandTypes.PrivacySourcesUpdate,
                new { },
                cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (exception is IpcClientException or IOException or TimeoutException or OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>True when the settings file asks for the Strict profile with all sources enabled.</summary>
    public static bool IsCompleteProfile(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var enabled = root.TryGetProperty("enabled", out var enabledElement) && enabledElement.GetBoolean();
            var profile = root.TryGetProperty("profile", out var profileElement) ? profileElement.GetInt32() : -1;
            var sources = root.TryGetProperty("enabledSourceIds", out var sourcesElement) && sourcesElement.GetArrayLength() > 0;
            return enabled && profile == (int)PrivacyShieldProfile.Strict && sources;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
