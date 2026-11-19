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

    private readonly List<PrivacyShieldBlockedEvent> _persisted = [];

    private readonly Timer _flushTimer;

    private int _count;

    private bool _disposed;

    public PrivacyShieldBlockedHistoryStore(string? path = null)
    {
        // History is deliberately kept in the service account's local profile: blocked domains
        // reveal browsing habits, so the file is not shared machine-wide like the settings.
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "privacy-shield-blocked.jsonl");
        _persisted.AddRange(ReadPersistedFromDisk());
        _count = _persisted.Count;
        _flushTimer = new Timer(_ => Flush(), null, FlushInterval, FlushInterval);
    }

    public string HistoryPath => _path;

    public void Append(PrivacyShieldBlockedEvent blocked)
    {
        var flush = false;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

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
            FlushLocked();
        }
    }

    private void FlushLocked()
    {
        if (_pending.Count == 0)
        {
            return;
        }

        try
        {
            var valid = _pending
                .Where(item => !string.IsNullOrWhiteSpace(item.Domain))
                .ToList();
            if (valid.Count == 0)
            {
                _pending.Clear();
                return;
            }

            if (valid.Count > MaxEntries)
            {
                valid = valid.Skip(valid.Count - MaxEntries).ToList();
            }

            if (_count + valid.Count > MaxEntries)
            {
                CompactLocked();
            }

            var directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("Privacy Shield history path has no directory.");
            Directory.CreateDirectory(directory);
            File.AppendAllLines(
                _path,
                valid.Select(item => JsonSerializer.Serialize(item, JsonOptions)),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            _persisted.AddRange(valid);

            if (_persisted.Count > MaxEntries)
            {
                _persisted.RemoveRange(0, _persisted.Count - MaxEntries);
            }

            _count = Math.Min(MaxEntries, _count + valid.Count);
            _pending.Clear();
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
        }
    }

    public IReadOnlyList<PrivacyShieldBlockedEvent> LoadRecent(int max = MaxEntries)
    {
        lock (_gate)
        {
            var limit = Math.Clamp(max, 1, MaxEntries);
            var startIndex = Math.Max(0, _persisted.Count - limit);
            var events = new List<PrivacyShieldBlockedEvent>((_persisted.Count - startIndex) + _pending.Count);
            for (var i = startIndex; i < _persisted.Count; i++)
            {
                events.Add(_persisted[i]);
            }

            // Newly blocked entries are still in RAM; show them before the periodic flush.
            foreach (var item in _pending)
            {
                if (!string.IsNullOrWhiteSpace(item.Domain))
                {
                    events.Add(item);
                }
            }

            return events
                .OrderByDescending(item => item.BlockedUtc)
                .Take(limit)
                .ToArray();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            try
            {
                _pending.Clear();
                _persisted.Clear();
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
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            FlushLocked();
            _disposed = true;
        }
    }

    private void CompactLocked()
    {
        var keepCount = MaxEntries / 2;
        var lines = File.Exists(_path)
            ? File.ReadLines(_path).TakeLast(keepCount).ToArray()
            : [];
        File.WriteAllLines(_path, lines, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        _count = lines.Length;
        if (_persisted.Count > keepCount)
        {
            _persisted.RemoveRange(0, _persisted.Count - keepCount);
        }
    }

    private List<PrivacyShieldBlockedEvent> ReadPersistedFromDisk()
    {
        var events = new List<PrivacyShieldBlockedEvent>();
        try
        {
            if (!File.Exists(_path))
            {
                return events;
            }

            foreach (var line in File.ReadLines(_path).TakeLast(MaxEntries))
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
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return events;
    }
}
