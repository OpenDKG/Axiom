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

    private readonly object _gate = new();
    private readonly string _path;
    private ProtectionSettings? _cached;
    private long _cachedWriteTicks = -1;
    private long _cachedLength = -1;

    public ProtectionSettingsStore(string? path = null)
    {
        _path = path ?? DefaultPath;
    }

    public static string DefaultPath => System.IO.Path.Combine(
        Axiom.Contracts.AxiomPaths.MachineDataDirectory,
        "protection.json");

    public string FilePath => _path;

    public ProtectionSettings Load()
    {
        lock (_gate)
        {
            try
            {
                var info = new FileInfo(_path);
                if (!info.Exists)
                {
                    _cached = null;
                    _cachedWriteTicks = -1;
                    _cachedLength = -1;
                    return new ProtectionSettings();
                }

                var writeTicks = info.LastWriteTimeUtc.Ticks;
                var length = info.Length;
                if (_cached is not null &&
                    writeTicks == _cachedWriteTicks &&
                    length == _cachedLength)
                {
                    return _cached;
                }

                var settings = JsonSerializer.Deserialize<ProtectionSettings>(File.ReadAllText(_path), JsonOptions);
                if (settings is null || settings.SchemaVersion != CurrentSchemaVersion)
                {
                    return new ProtectionSettings();
                }

                var normalized = settings with
                {
                    Decisions = (settings.Decisions ?? [])
                        .Where(decision => !string.IsNullOrWhiteSpace(decision.AppPath))
                        .ToList(),
                    Pending = (settings.Pending ?? [])
                        .Where(item => !string.IsNullOrWhiteSpace(item.AppPath))
                        .ToList(),
                    Dismissals = (settings.Dismissals ?? [])
                        .Where(item => !string.IsNullOrWhiteSpace(item.AppPath))
                        .ToList(),
                };

                _cached = normalized;
                _cachedWriteTicks = writeTicks;
                _cachedLength = length;
                return normalized;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
            {
                return new ProtectionSettings();
            }
        }
    }

    public bool Save(ProtectionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        lock (_gate)
        {
            try
            {
                var directory = System.IO.Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var normalized = settings with
                {
                    SchemaVersion = CurrentSchemaVersion,
                    Decisions = (settings.Decisions ?? [])
                        .Where(decision => !string.IsNullOrWhiteSpace(decision.AppPath))
                        .ToList(),
                    Pending = (settings.Pending ?? [])
                        .Where(item => !string.IsNullOrWhiteSpace(item.AppPath))
                        .ToList(),
                    Dismissals = (settings.Dismissals ?? [])
                        .Where(item => !string.IsNullOrWhiteSpace(item.AppPath))
                        .ToList(),
                };

                var payload = JsonSerializer.Serialize(normalized, JsonOptions);

                // A predictable temp name lets another user pre-create the file and keep ownership of
                // the saved settings. Use a random name and move over the target atomically.
                var temporary = _path + "." + Path.GetRandomFileName() + ".tmp";
                try
                {
                    File.WriteAllText(temporary, payload);
                    File.Move(temporary, _path, overwrite: true);
                }
                finally
                {
                    if (File.Exists(temporary))
                    {
                        File.Delete(temporary);
                    }
                }

                var info = new FileInfo(_path);
                _cached = normalized;
                _cachedWriteTicks = info.Exists ? info.LastWriteTimeUtc.Ticks : -1;
                _cachedLength = info.Exists ? info.Length : -1;
                return true;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return false;
            }
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

    /// <summary>Durable ask queue. Entries remain until Block/Allow/Dismiss even if the socket ends.</summary>
    public IReadOnlyList<ProtectionPendingApp>? Pending { get; init; } = [];

    /// <summary>Dismissed applications, kept to suppress re-showing until a new connection appears.</summary>
    public IReadOnlyList<ProtectionDismissal>? Dismissals { get; init; } = [];
}
