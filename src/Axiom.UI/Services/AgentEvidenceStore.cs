// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.IO;
using System.Text.Json;

namespace Axiom.UI.Services;

/// <summary>One bounded, non-sensitive event written by a Axiom-owned agent hook.</summary>
public sealed record AgentEvidenceEvent(
    DateTimeOffset Timestamp,
    string Framework,
    string EventType,
    string Tool,
    string Decision,
    string GuardStatus,
    long DurationMs,
    string ErrorCode)
{
    public string Session { get; init; } = string.Empty;

    public string Call { get; init; } = string.Empty;

    public string Channel { get; init; } = string.Empty;

    public string EffectiveChannel
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Channel))
            {
                return Channel.Trim().ToUpperInvariant();
            }

            if (IsFailure)
            {
                return string.Equals(Decision, "block", StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(GuardStatus, "failed_closed", StringComparison.OrdinalIgnoreCase)
                    ? "FAILED_CLOSED"
                    : "FAILED_OPEN";
            }

            return string.Equals(EventType, "GUARD_BLOCKED", StringComparison.OrdinalIgnoreCase)
                ? "HOST_DENY_SENT"
                : "DETECTOR_ONLY";
        }
    }

    public string TimeText => Timestamp == DateTimeOffset.MinValue
        ? "—"
        : Timestamp.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public bool IsFailure => EventType is "GUARD_FAILED" or "GUARD_TIMEOUT";
}

/// <summary>
/// Reads the local hook evidence channel. Bridges write only framework, event type, tool name and
/// decision; they never write prompts, paths, commands, tokens or file contents.
/// </summary>
public sealed class AgentEvidenceStore
{
    private readonly object _cacheGate = new();
    private List<AgentEvidenceEvent> _cachedEvents = [];
    private long _cachedLength = -1;
    private long _cachedWriteTicks = -1;
    private int _cachedMax;

    public AgentEvidenceStore(string? path = null)
    {
        EvidencePath = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "agent-evidence.jsonl");
    }

    public string EvidencePath { get; }

    public IReadOnlyList<AgentEvidenceEvent> ReadRecent(int max = 200)
    {
        if (max <= 0)
        {
            return [];
        }

        try
        {
            var info = new FileInfo(EvidencePath);
            if (!info.Exists || info.Length == 0)
            {
                return [];
            }

            var writeTicks = info.LastWriteTimeUtc.Ticks;
            var length = info.Length;

            lock (_cacheGate)
            {
                if (length == _cachedLength &&
                    writeTicks == _cachedWriteTicks &&
                    max <= _cachedMax)
                {
                    return _cachedEvents.Count <= max
                        ? _cachedEvents
                        : _cachedEvents.Skip(_cachedEvents.Count - max).ToArray();
                }
            }

            var readTarget = Math.Max(max, 500);
            var events = ReadTailEvents(EvidencePath, length, readTarget);

            lock (_cacheGate)
            {
                _cachedEvents = events;
                _cachedLength = length;
                _cachedWriteTicks = writeTicks;
                _cachedMax = readTarget;
            }

            return events.Count <= max
                ? events
                : events.Skip(events.Count - max).ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static List<AgentEvidenceEvent> ReadTailEvents(string path, long fileLength, int maxEvents)
    {
        var windowBytes = Math.Min(fileLength, Math.Max(65_536L, maxEvents * 512L));
        while (true)
        {
            var startOffset = Math.Max(0L, fileLength - windowBytes);
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (startOffset > 0)
            {
                stream.Seek(startOffset, SeekOrigin.Begin);
            }

            using var reader = new StreamReader(stream);
            if (startOffset > 0)
            {
                _ = reader.ReadLine();
            }

            var ring = new Queue<AgentEvidenceEvent>(Math.Min(maxEvents, 1024));
            while (reader.ReadLine() is { } line)
            {
                if (string.IsNullOrWhiteSpace(line) || TryParse(line) is not { } item)
                {
                    continue;
                }

                if (ring.Count == maxEvents)
                {
                    _ = ring.Dequeue();
                }

                ring.Enqueue(item);
            }

            if (ring.Count >= maxEvents || startOffset == 0)
            {
                return [.. ring];
            }

            windowBytes = windowBytes >= fileLength / 2
                ? fileLength
                : windowBytes * 2;
        }
    }

    public AgentEvidenceEvent? Latest(string framework, TimeSpan? maxAge = null)
    {
        var cutoff = maxAge is null ? DateTimeOffset.MinValue : DateTimeOffset.UtcNow - maxAge.Value;
        return ReadRecent(500)
            .Where(item => string.Equals(item.Framework, framework, StringComparison.OrdinalIgnoreCase))
            .Where(item => item.Timestamp != DateTimeOffset.MinValue && item.Timestamp >= cutoff)
            .OrderByDescending(item => item.Timestamp)
            .FirstOrDefault();
    }

    private static AgentEvidenceEvent? TryParse(string line)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var timestamp = root.TryGetProperty("timestampUtc", out var time) &&
                            time.ValueKind == JsonValueKind.String &&
                            DateTimeOffset.TryParse(time.GetString(), CultureInfo.InvariantCulture,
                                DateTimeStyles.AssumeUniversal, out var parsed)
                ? parsed
                : DateTimeOffset.MinValue;

            return new AgentEvidenceEvent(
                timestamp,
                ReadString(root, "framework"),
                ReadString(root, "eventType"),
                ReadString(root, "tool"),
                ReadString(root, "decision"),
                ReadString(root, "guardStatus"),
                root.TryGetProperty("durationMs", out var duration) && duration.TryGetInt64(out var ms) ? ms : 0,
                ReadString(root, "errorCode"))
            {
                Session = ReadString(root, "session"),
                Call = ReadString(root, "call"),
                Channel = ReadString(root, "channel"),
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;
}
