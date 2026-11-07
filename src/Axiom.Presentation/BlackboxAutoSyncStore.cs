// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;

namespace Axiom.Presentation;

public sealed record BlackboxAutoSyncSettings(
    bool Enabled,
    DateTimeOffset LastAttemptUtc,
    string LastStatus);

/// <summary>Per-user opt-in for incremental verified-graph catch-up. It stores no credentials.</summary>
public sealed class BlackboxAutoSyncStore
{
    private readonly string _path;

    public BlackboxAutoSyncStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "blackbox-auto-sync.json");
    }

    public string SettingsPath => _path;

    public BlackboxAutoSyncSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return Empty();
            }

            using var document = JsonDocument.Parse(File.ReadAllText(_path));
            var root = document.RootElement;
            return new BlackboxAutoSyncSettings(
                root.TryGetProperty("enabled", out var enabled) && enabled.GetBoolean(),
                root.TryGetProperty("lastAttemptUtc", out var lastAttempt) &&
                lastAttempt.TryGetDateTimeOffset(out var timestamp)
                    ? timestamp
                    : DateTimeOffset.MinValue,
                root.TryGetProperty("lastStatus", out var lastStatus)
                    ? lastStatus.GetString() ?? string.Empty
                    : string.Empty);
        }
        catch (Exception exception) when (exception is
                     JsonException or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            return Empty();
        }
    }

    public void Save(BlackboxAutoSyncSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("Blackbox auto-sync settings path has no directory.");
        Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(new
        {
            enabled = settings.Enabled,
            lastAttemptUtc = settings.LastAttemptUtc,
            lastStatus = settings.LastStatus,
        });
        File.WriteAllText(_path, json);
    }

    private static BlackboxAutoSyncSettings Empty() =>
        new(false, DateTimeOffset.MinValue, "Auto-sync is off.");
}
