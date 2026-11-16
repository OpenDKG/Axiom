// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;

namespace Axiom.Presentation;

public sealed record UpdateSettings(
    bool CheckForUpdates,
    string DismissedVersion,
    DateTimeOffset LastCheckedUtc);

/// <summary>
/// Small per-user preference store for update checks and per-version dismissal.
/// Stores no installation ID, hardware identifier, or credentials.
/// </summary>
public sealed class UpdateSettingsStore
{
    private readonly string _path;

    public UpdateSettingsStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "updates.json");
    }

    public string SettingsPath => _path;

    public event EventHandler? Changed;

    public UpdateSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return Defaults();
            }

            using var document = JsonDocument.Parse(File.ReadAllText(_path));
            var root = document.RootElement;
            var checkForUpdates = !root.TryGetProperty("checkForUpdates", out var check) ||
                                  check.ValueKind != JsonValueKind.False;
            var dismissed = root.TryGetProperty("dismissedVersion", out var dismissedProp) &&
                            dismissedProp.ValueKind == JsonValueKind.String
                ? dismissedProp.GetString() ?? string.Empty
                : string.Empty;
            var lastChecked = root.TryGetProperty("lastCheckedUtc", out var lastProp) &&
                              lastProp.TryGetDateTimeOffset(out var timestamp)
                ? timestamp
                : DateTimeOffset.MinValue;

            return new UpdateSettings(checkForUpdates, dismissed, lastChecked);
        }
        catch (Exception exception) when (exception is
                     JsonException or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            return Defaults();
        }
    }

    public void Save(UpdateSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(new
            {
                checkForUpdates = settings.CheckForUpdates,
                dismissedVersion = settings.DismissedVersion,
                lastCheckedUtc = settings.LastCheckedUtc,
            });
            File.WriteAllText(_path, json);
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // A restricted profile must not crash Settings or background update checks.
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    public static UpdateSettings Defaults() =>
        new(CheckForUpdates: true, DismissedVersion: string.Empty, LastCheckedUtc: DateTimeOffset.MinValue);
}
