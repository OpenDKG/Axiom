// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Ai;

namespace Axiom.Presentation;

/// <summary>
/// Stores the optional AI provider settings. The API key is protected with Windows DPAPI for the
/// current user and is never written in plaintext or included in the analysis audit log.
/// </summary>
public sealed class AiAnalystSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly string _path;
    private readonly IApiKeyProtector _protector;

    public AiAnalystSettingsStore(IApiKeyProtector protector, string? path = null)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "ai-analyst.json");
    }

    public string SettingsPath => _path;

    public (AiAnalystSettings Settings, string ApiKey) Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return (new AiAnalystSettings(), string.Empty);
            }

            using var document = JsonDocument.Parse(File.ReadAllText(_path));
            var root = document.RootElement;
            var settings = JsonSerializer.Deserialize<AiAnalystSettings>(
                               root.GetRawText(),
                               JsonOptions)
                           ?? new AiAnalystSettings();
            var protectedKey = root.TryGetProperty("apiKeyProtected", out var keyElement)
                ? keyElement.GetString()
                : null;

            if (string.IsNullOrWhiteSpace(protectedKey))
            {
                return (settings, string.Empty);
            }

            return (settings, _protector.Unprotect(protectedKey) ?? string.Empty);
        }
        catch (Exception exception) when (exception is
                     CryptographicException or JsonException or IOException or FormatException or
                     InvalidOperationException or UnauthorizedAccessException)
        {
            return (new AiAnalystSettings(), string.Empty);
        }
    }

    public bool Save(AiAnalystSettings settings, string? apiKey = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        try
        {
            var directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("AI analyst settings path has no directory.");
            Directory.CreateDirectory(directory);

            string? existingProtected = null;
            if (File.Exists(_path))
            {
                using var existingDocument = JsonDocument.Parse(File.ReadAllText(_path));
                existingProtected = existingDocument.RootElement.TryGetProperty(
                    "apiKeyProtected",
                    out var element)
                    ? element.GetString()
                    : null;
            }

            var protectedKey = apiKey is null
                ? existingProtected
                : string.IsNullOrWhiteSpace(apiKey)
                    ? string.Empty
                    : _protector.Protect(apiKey);

            var json = JsonSerializer.Serialize(settings, JsonOptions);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                foreach (var property in root.EnumerateObject())
                {
                    property.WriteTo(writer);
                }

                writer.WriteString("apiKeyProtected", protectedKey);
                writer.WriteEndObject();
            }

            File.WriteAllText(
                _path,
                Encoding.UTF8.GetString(stream.ToArray()),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            return true;
        }
        catch (Exception exception) when (exception is
                     CryptographicException or JsonException or IOException or
                     InvalidOperationException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
