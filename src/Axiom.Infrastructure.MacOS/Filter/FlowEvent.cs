// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;

namespace Axiom.Infrastructure.MacOS.Filter;

public enum FlowEventType
{
    Open = 0,
    Stats = 1,
    Close = 2,
    Hello = 3,
}

/// <summary>One parsed line of the filter -> daemon stream (docs/MACOS_ARCHITECTURE.md section 3.2).</summary>
public sealed record FlowEvent
{
    public required FlowEventType Type { get; init; }

    public string Id { get; init; } = string.Empty;

    public DateTimeOffset? Timestamp { get; init; }

    public int ProcessId { get; init; }

    public string Path { get; init; } = string.Empty;

    public string Direction { get; init; } = string.Empty;

    public string Protocol { get; init; } = string.Empty;

    public string LocalAddress { get; init; } = string.Empty;

    public int LocalPort { get; init; }

    public string RemoteAddress { get; init; } = string.Empty;

    public int RemotePort { get; init; }

    public string RemoteHost { get; init; } = string.Empty;

    public string Verdict { get; init; } = string.Empty;

    public string? RuleId { get; init; }

    public long? BytesIn { get; init; }

    public long? BytesOut { get; init; }

    public string? Version { get; init; }

    public long? Generation { get; init; }
}

/// <summary>
/// Defensive parser for flow-event lines. Anything that is not a JSON object with a known
/// <c>type</c> (and an <c>id</c> for flow events) is rejected; wrong field types are ignored rather
/// than trusted. Strings are capped so a hostile line cannot inflate the flow table.
/// </summary>
public static class FlowEventParser
{
    public const int MaxStringLength = 1024;

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 4,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
    };

    public static FlowEvent? TryParse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(line, DocumentOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            FlowEventType? type = GetString(root, "type") switch
            {
                "flow.open" => FlowEventType.Open,
                "flow.stats" => FlowEventType.Stats,
                "flow.close" => FlowEventType.Close,
                "filter.hello" => FlowEventType.Hello,
                _ => null,
            };

            if (type is not { } eventType)
            {
                return null;
            }

            var id = GetString(root, "id");
            if (eventType != FlowEventType.Hello && id.Length == 0)
            {
                return null;
            }

            return new FlowEvent
            {
                Type = eventType,
                Id = id,
                Timestamp = GetTimestamp(root, "ts"),
                ProcessId = (int)Math.Clamp(GetLong(root, "pid") ?? 0, 0, int.MaxValue),
                Path = GetString(root, "path"),
                Direction = GetString(root, "direction").ToLowerInvariant(),
                Protocol = GetString(root, "protocol").ToLowerInvariant(),
                LocalAddress = GetString(root, "localAddress"),
                LocalPort = Port(GetLong(root, "localPort")),
                RemoteAddress = GetString(root, "remoteAddress"),
                RemotePort = Port(GetLong(root, "remotePort")),
                RemoteHost = GetString(root, "remoteHost"),
                Verdict = GetString(root, "verdict").ToLowerInvariant(),
                RuleId = GetString(root, "ruleId") is { Length: > 0 } ruleId ? ruleId : null,
                BytesIn = NonNegative(GetLong(root, "bytesIn")),
                BytesOut = NonNegative(GetLong(root, "bytesOut")),
                Version = GetString(root, "version") is { Length: > 0 } version ? version : null,
                Generation = GetLong(root, "generation"),
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string GetString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return string.Empty;
        }

        var text = value.GetString() ?? string.Empty;
        return text.Length > MaxStringLength ? text[..MaxStringLength] : text;
    }

    private static long? GetLong(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt64(out var number)
            ? number
            : null;

    private static DateTimeOffset? GetTimestamp(JsonElement root, string name)
    {
        var text = GetString(root, name);
        return DateTimeOffset.TryParse(
            text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var value)
            ? value
            : null;
    }

    private static int Port(long? value) => value is >= 0 and <= 65535 ? (int)value.Value : 0;

    private static long? NonNegative(long? value) => value is >= 0 ? value : null;
}
