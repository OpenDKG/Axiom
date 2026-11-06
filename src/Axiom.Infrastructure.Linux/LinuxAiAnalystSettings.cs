// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Ai;

namespace Axiom.Infrastructure.Linux;

/// <summary>
/// XDG settings for the optional AI analyst. It stores only endpoint/model/redaction choices; the
/// provider key is kept by Secret Service and is never written to this file.
/// </summary>
public sealed class LinuxAiAnalystSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly string _path;

    public LinuxAiAnalystSettings(string? path = null)
    {
        _path = path ?? Path.Combine(ConfigDirectory(), "axiom", "ai-analyst.json");
    }

    public string SettingsPath => _path;

    public AiAnalystSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new AiAnalystSettings();
            }

            var info = new FileInfo(_path);
            if (info.Length is 0 or > 64 * 1024)
            {
                return new AiAnalystSettings();
            }

            return JsonSerializer.Deserialize<AiAnalystSettings>(File.ReadAllText(_path), JsonOptions)
                   ?? new AiAnalystSettings();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new AiAnalystSettings();
        }
    }

    public void Save(AiAnalystSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var directory = Path.GetDirectoryName(_path)!;
        if (!Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
            File.SetUnixFileMode(
                directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        // A unique temporary file per save: a shared name lets concurrent writers publish each
        // other's content or fail when one has already moved the file.
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(settings, JsonOptions));
            File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temporary, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static string ConfigDirectory()
    {
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        return string.IsNullOrWhiteSpace(xdg)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config")
            : xdg;
    }
}
