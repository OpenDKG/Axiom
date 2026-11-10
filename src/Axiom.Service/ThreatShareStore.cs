// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Threat;

namespace Axiom.Service;

/// <summary>
/// Durable queue of indicator candidates and their outcome. Stored in the service account's local
/// profile next to the blocked-query history: it holds domains an agent fetched, not general
/// browsing data, and only what the user chose to consider sharing.
/// </summary>
public sealed class ThreatShareStore
{
    public const int MaxItems = 500;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly object _gate = new();

    private readonly string _path;

    public ThreatShareStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Axiom.Contracts.AxiomPaths.ServicePrivateDataDirectory,
            "threat-share.json");
    }

    public string StorePath => _path;

    public IReadOnlyList<ThreatShareItem> Load()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(_path))
                {
                    return [];
                }

                return JsonSerializer.Deserialize<List<ThreatShareItem>>(
                           File.ReadAllText(_path),
                           JsonOptions)
                       ?? [];
            }
            catch (Exception exception) when (exception is
                         IOException or UnauthorizedAccessException or JsonException)
            {
                return [];
            }
        }
    }

    public bool Save(IReadOnlyList<ThreatShareItem> items)
    {
        lock (_gate)
        {
            try
            {
                var directory = Path.GetDirectoryName(_path)
                    ?? throw new InvalidOperationException("Threat share store path has no directory.");
                Directory.CreateDirectory(directory);

                var bounded = items.Count <= MaxItems ? items : items.TakeLast(MaxItems).ToArray();
                var temp = _path + ".tmp";
                File.WriteAllText(
                    temp,
                    JsonSerializer.Serialize(bounded, JsonOptions),
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                File.Move(temp, _path, overwrite: true);
                return true;
            }
            catch (Exception exception) when (exception is
                         IOException or UnauthorizedAccessException or JsonException)
            {
                return false;
            }
        }
    }
}
