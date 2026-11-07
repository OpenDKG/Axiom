// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;

namespace Axiom.Presentation;

public sealed record OnboardingSettings(bool Completed, bool Skipped, bool Dkg, bool Blackbox);

/// <summary>Marks whether the first-run setup was completed or explicitly skipped.</summary>
public static class OnboardingStore
{
    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Axiom",
        "onboarding.json");

    public static bool IsCompleted => TryLoad()?.Completed == true;

    public static OnboardingSettings? TryLoad()
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            var root = document.RootElement;
            return new OnboardingSettings(
                root.TryGetProperty("completed", out var completed) && completed.GetBoolean(),
                root.TryGetProperty("skipped", out var skipped) && skipped.GetBoolean(),
                root.TryGetProperty("dkg", out var dkg) && dkg.GetBoolean(),
                root.TryGetProperty("blackbox", out var blackbox) && blackbox.GetBoolean());
        }
        catch (Exception exception) when (exception is JsonException or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public static void Save(OnboardingSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var directory = Path.GetDirectoryName(SettingsPath)
            ?? throw new InvalidOperationException("Onboarding settings path has no directory.");
        Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(new
        {
            completed = settings.Completed,
            skipped = settings.Skipped,
            dkg = settings.Dkg,
            blackbox = settings.Blackbox,
        });

        File.WriteAllText(SettingsPath, json);
    }
}
