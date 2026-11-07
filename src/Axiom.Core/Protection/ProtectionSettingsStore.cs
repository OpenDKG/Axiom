// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Protection;

namespace Axiom.Core.Protection;

/// <summary>
/// Durable, machine-wide shield consent and decisions. The file lives under ProgramData so the
/// elevated service and the interactive UI read the same state. Writes are atomic; a corrupted
/// file is ignored rather than treated as consent.
/// </summary>
public sealed class ProtectionSettingsStore
{
    public const int CurrentSchemaVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly string _path;

    public ProtectionSettingsStore(string? path = null)
    {
        _path = path ?? DefaultPath;
    }

    public static string DefaultPath => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Axiom",
        "protection.json");

    public string FilePath => _path;

    public ProtectionSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new ProtectionSettings();
            }

            var settings = JsonSerializer.Deserialize<ProtectionSettings>(File.ReadAllText(_path), JsonOptions);
            if (settings is null || settings.SchemaVersion != CurrentSchemaVersion)
            {
                return new ProtectionSettings();
            }

            return settings with
            {
                Decisions = (settings.Decisions ?? [])
                    .Where(decision => !string.IsNullOrWhiteSpace(decision.AppPath))
                    .ToList(),
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new ProtectionSettings();
        }
    }

    public bool Save(ProtectionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        try
        {
            var directory = System.IO.Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var payload = JsonSerializer.Serialize(
                settings with { SchemaVersion = CurrentSchemaVersion },
                JsonOptions);

            var temporary = _path + ".tmp";
            File.WriteAllText(temporary, payload);
            File.Move(temporary, _path, overwrite: true);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

/// <summary>On-disk shield state. Absent or invalid files mean "protection off".</summary>
public sealed record ProtectionSettings
{
    public int SchemaVersion { get; init; } = ProtectionSettingsStore.CurrentSchemaVersion;

    public bool Enabled { get; init; }

    public string DefaultPolicy { get; init; } = "ask";

    public bool AgentLockdown { get; init; }

    public DateTimeOffset? EnabledUtc { get; init; }

    public string? AllowedSid { get; init; }

    public IReadOnlyList<ProtectionDecision>? Decisions { get; init; } = [];
}
