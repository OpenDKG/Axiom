// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Privacy;

namespace Axiom.Service;

/// <summary>Per-user Privacy Shield configuration. No DNS query history is stored here.</summary>
public sealed class PrivacyShieldSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private readonly string _path;

    public PrivacyShieldSettingsStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "privacy-shield.json");
    }

    public string SettingsPath => _path;

    public PrivacyShieldSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new PrivacyShieldSettings();
            }

            return JsonSerializer.Deserialize<PrivacyShieldSettings>(
                       File.ReadAllText(_path),
                       JsonOptions)
                   ?? new PrivacyShieldSettings();
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return new PrivacyShieldSettings();
        }
    }

    public bool Save(PrivacyShieldSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        try
        {
            var directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("Privacy Shield settings path has no directory.");
            Directory.CreateDirectory(directory);

            var temporary = _path + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(
                temporary,
                JsonSerializer.Serialize(settings, JsonOptions),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(temporary, _path, overwrite: true);
            return true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }
}
