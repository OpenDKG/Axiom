// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Privacy;

namespace Axiom.Service;

/// <summary>
/// Bounded local blocked-query history. Only blocked domains, category and time are stored; allowed
/// queries, clients and process metadata are not. The file is compacted when it reaches the limit.
/// </summary>
public sealed class PrivacyShieldBlockedHistoryStore
{
    public const int MaxEntries = 1_000;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly object _gate = new();

    private readonly string _path;

    private int _count;

    public PrivacyShieldBlockedHistoryStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "privacy-shield-blocked.jsonl");
        _count = CountLines();
    }

    public string HistoryPath => _path;

    public void Append(PrivacyShieldBlockedEvent blocked)
    {
        lock (_gate)
        {
            try
            {
                if (_count >= MaxEntries)
                {
                    CompactLocked();
                }

                var directory = Path.GetDirectoryName(_path)
                    ?? throw new InvalidOperationException("Privacy Shield history path has no directory.");
                Directory.CreateDirectory(directory);
                File.AppendAllText(
                    _path,
                    JsonSerializer.Serialize(blocked, JsonOptions) + "\n",
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                _count++;
            }
            catch (Exception exception) when (exception is
                         IOException or UnauthorizedAccessException or JsonException)
            {
            }
        }
    }

    public IReadOnlyList<PrivacyShieldBlockedEvent> LoadRecent(int max = MaxEntries)
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(_path))
                {
                    return [];
                }

                var limit = Math.Clamp(max, 1, MaxEntries);
                var events = new List<PrivacyShieldBlockedEvent>();
                foreach (var line in File.ReadLines(_path).TakeLast(limit))
                {
                    try
                    {
                        var item = JsonSerializer.Deserialize<PrivacyShieldBlockedEvent>(line, JsonOptions);
                        if (item is not null && !string.IsNullOrWhiteSpace(item.Domain))
                        {
                            events.Add(item);
                        }
                    }
                    catch (JsonException)
                    {
                    }
                }

                events.Reverse();
                return events;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return [];
            }
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            try
            {
                if (File.Exists(_path))
                {
                    File.Delete(_path);
                }

                _count = 0;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private void CompactLocked()
    {
        var lines = File.Exists(_path)
            ? File.ReadLines(_path).TakeLast(MaxEntries / 2).ToArray()
            : [];
        File.WriteAllLines(_path, lines, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        _count = lines.Length;
    }

    private int CountLines()
    {
        try
        {
            return File.Exists(_path) ? File.ReadLines(_path).Count() : 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }
}
