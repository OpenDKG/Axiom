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
        Axiom.Contracts.AxiomPaths.MachineDataDirectory,
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
                Pending = (settings.Pending ?? [])
                    .Where(item => !string.IsNullOrWhiteSpace(item.AppPath))
                    .ToList(),
                Dismissals = (settings.Dismissals ?? [])
                    .Where(item => !string.IsNullOrWhiteSpace(item.AppPath))
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
            if (!OperatingSystem.IsWindows())
            {
                // Machine-wide state written by the root daemon: not readable by other local users.
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

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

    /// <summary>
    /// macOS: uid of the account that installed the daemon; it may send IPC write commands.
    /// Recorded by <c>axiomd --install-service</c>. Ignored on Windows (which uses <see cref="AllowedSid"/>).
    /// </summary>
    public uint? AllowedUid { get; init; }

    /// <summary>macOS: members of the <c>admin</c> group may also send IPC write commands. Ignored on Windows.</summary>
    public bool AllowAdminGroupWrites { get; init; } = true;

    public IReadOnlyList<ProtectionDecision>? Decisions { get; init; } = [];

    /// <summary>Durable ask queue. Entries remain until Block/Allow/Dismiss even if the socket ends.</summary>
    public IReadOnlyList<ProtectionPendingApp>? Pending { get; init; } = [];

    /// <summary>Dismissed applications, kept to suppress re-showing until a new connection appears.</summary>
    public IReadOnlyList<ProtectionDismissal>? Dismissals { get; init; } = [];
}
