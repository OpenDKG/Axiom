// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;

namespace Netpetra.UI.Services;

public sealed record StartupSettings(
    bool StartWithWindows,
    bool StartMinimized,
    string LastKnownExecutablePath,
    DateTimeOffset UpdatedUtc);

/// <summary>Small per-user startup preference store. It never stores credentials or agent data.</summary>
public sealed class StartupSettingsStore
{
    private readonly string _path;

    public StartupSettingsStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Netpetra",
            "startup.json");
    }

    public string SettingsPath => _path;

    public StartupSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return Empty();
            }

            using var document = JsonDocument.Parse(File.ReadAllText(_path));
            var root = document.RootElement;
            return new StartupSettings(
                root.TryGetProperty("startWithWindows", out var startWithWindows) &&
                startWithWindows.GetBoolean(),
                root.TryGetProperty("startMinimized", out var startMinimized) &&
                startMinimized.GetBoolean(),
                root.TryGetProperty("lastKnownExecutablePath", out var executablePath)
                    ? executablePath.GetString() ?? string.Empty
                    : string.Empty,
                root.TryGetProperty("updatedUtc", out var updated) &&
                updated.TryGetDateTimeOffset(out var timestamp)
                    ? timestamp
                    : DateTimeOffset.MinValue);
        }
        catch (Exception exception) when (exception is
                     JsonException or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            return Empty();
        }
    }

    public void Save(StartupSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("Startup settings path has no directory.");
        Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(new
        {
            startWithWindows = settings.StartWithWindows,
            startMinimized = settings.StartMinimized,
            lastKnownExecutablePath = settings.LastKnownExecutablePath,
            updatedUtc = settings.UpdatedUtc,
        });
        File.WriteAllText(_path, json);
    }

    private static StartupSettings Empty() =>
        new(false, false, string.Empty, DateTimeOffset.MinValue);
}
