// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Privacy;

namespace Axiom.Service;

/// <summary>
/// Bounded local blocked-query history. Only blocked domains, category, time and the app identity
/// the UI groups by are stored; allowed queries, clients and endpoints are not. New events are kept
/// in memory and appended in one write every 30 seconds, so a busy resolver does not turn each
/// blocked lookup into a file write. The file is compacted when it reaches the limit.
/// </summary>
public sealed class PrivacyShieldBlockedHistoryStore : IDisposable
{
    public const int MaxEntries = 1_000;

    private const int FlushThreshold = 32;

    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly object _gate = new();

    private readonly string _path;

    private readonly List<PrivacyShieldBlockedEvent> _pending = [];

    private readonly Timer _flushTimer;

    private int _count;

    public PrivacyShieldBlockedHistoryStore(string? path = null)
    {
        // History is deliberately kept in the service account's local profile: blocked domains
        // reveal browsing habits, so the file is not shared machine-wide like the settings.
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "privacy-shield-blocked.jsonl");
        _count = CountLines();
        _flushTimer = new Timer(_ => Flush(), null, FlushInterval, FlushInterval);
    }

    public string HistoryPath => _path;

    public void Append(PrivacyShieldBlockedEvent blocked)
    {
        var flush = false;
        lock (_gate)
        {
            _pending.Add(blocked);
            flush = _pending.Count >= FlushThreshold;
        }

        if (flush)
        {
            Flush();
        }
    }

    public void Flush()
    {
        lock (_gate)
        {
            if (_pending.Count == 0)
            {
                return;
            }

            try
            {
                if (_count + _pending.Count > MaxEntries)
                {
                    CompactLocked();
                }

                var directory = Path.GetDirectoryName(_path)
                    ?? throw new InvalidOperationException("Privacy Shield history path has no directory.");
                Directory.CreateDirectory(directory);
                File.AppendAllLines(
                    _path,
                    _pending.Select(item => JsonSerializer.Serialize(item, JsonOptions)),
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                _count += _pending.Count;
                _pending.Clear();
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
                var limit = Math.Clamp(max, 1, MaxEntries);
                var events = new List<PrivacyShieldBlockedEvent>();
                if (File.Exists(_path))
                {
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
                }

                // Newly blocked entries are still in RAM; show them before the periodic flush.
                events.AddRange(_pending);
                return events
                    .OrderByDescending(item => item.BlockedUtc)
                    .Take(limit)
                    .ToArray();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return _pending.ToArray();
            }
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            try
            {
                _pending.Clear();
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

    public void Dispose()
    {
        _flushTimer.Dispose();
        Flush();
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
