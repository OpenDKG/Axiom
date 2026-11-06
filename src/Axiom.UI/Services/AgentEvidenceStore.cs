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
        try
        {
            if (!File.Exists(EvidencePath))
            {
                return [];
            }

            var events = new List<AgentEvidenceEvent>();
            foreach (var line in File.ReadLines(EvidencePath).TakeLast(max))
            {
                if (TryParse(line) is { } item)
                {
                    events.Add(item);
                }
            }

            return events;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
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
                ReadString(root, "errorCode"));
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
