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

    /// <summary><c>filter.rules</c>: outcome of the last rules reload (review #6).</summary>
    Rules = 4,
}

/// <summary>One rule the filter skipped, with the filter's reason (docs/MACOS_ARCHITECTURE.md section 3.2).</summary>
public sealed record FilterRejectedRule(string Id, string Reason);

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

    /// <summary><c>filter.rules</c>: enabled rules the filter enforces from the table in force.</summary>
    public int? Applied { get; init; }

    /// <summary><c>filter.rules</c>: rules skipped by the filter (capped at <see cref="FlowEventParser.MaxRejectedRules"/>).</summary>
    public IReadOnlyList<FilterRejectedRule> Rejected { get; init; } = [];

    /// <summary><c>filter.rules</c>: why the whole rules file was rejected; null when it loaded.</summary>
    public string? Error { get; init; }

    /// <summary>
    /// <c>filter.rules</c>: ids of the rules the filter enforces from the table in force (review #2
    /// MAC-1, optional additive field; null when the extension predates it or the list exceeded
    /// <see cref="FlowEventParser.MaxRuleIds"/>, i.e. "unknown", never a truncated list).
    /// </summary>
    public IReadOnlyList<string>? RuleIds { get; init; }

    /// <summary><c>filter.hello</c> / <c>filter.rules</c>: events the filter dropped so far (monotonic per process).</summary>
    public long? Dropped { get; init; }
}

/// <summary>
/// Defensive parser for flow-event lines. Anything that is not a JSON object with a known
/// <c>type</c> (and an <c>id</c> for flow events) is rejected; wrong field types are ignored rather
/// than trusted. Strings are capped so a hostile line cannot inflate the flow table.
/// </summary>
public static class FlowEventParser
{
    public const int MaxStringLength = 1024;

    /// <summary>Upper bound on the rejected-rule entries kept from one <c>filter.rules</c> event.</summary>
    public const int MaxRejectedRules = 256;

    /// <summary>Upper bound on the <c>ruleIds</c> echoed by one <c>filter.rules</c> event; above it the list is treated as unknown.</summary>
    public const int MaxRuleIds = 16384;

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
                "filter.rules" => FlowEventType.Rules,
                _ => null,
            };

            if (type is not { } eventType)
            {
                return null;
            }

            var id = GetString(root, "id");
            if (eventType is not (FlowEventType.Hello or FlowEventType.Rules) && id.Length == 0)
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
                Applied = eventType == FlowEventType.Rules
                    ? (int?)Math.Clamp(NonNegative(GetLong(root, "applied")) ?? 0, 0, int.MaxValue)
                    : null,
                Rejected = eventType == FlowEventType.Rules ? GetRejected(root) : [],
                RuleIds = eventType == FlowEventType.Rules ? GetRuleIds(root) : null,
                Error = GetString(root, "error") is { Length: > 0 } error ? error : null,
                Dropped = NonNegative(GetLong(root, "dropped")),
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static List<FilterRejectedRule> GetRejected(JsonElement root)
    {
        if (!root.TryGetProperty("rejected", out var list) || list.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var rejected = new List<FilterRejectedRule>();
        foreach (var entry in list.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var id = GetString(entry, "id");
            var reason = GetString(entry, "reason");
            if (id.Length == 0 && reason.Length == 0)
            {
                continue;
            }

            rejected.Add(new FilterRejectedRule(id.Length == 0 ? "?" : id, reason.Length == 0 ? "rejected by the filter" : reason));
            if (rejected.Count >= MaxRejectedRules)
            {
                break;
            }
        }

        return rejected;
    }

    private static List<string>? GetRuleIds(JsonElement root)
    {
        if (!root.TryGetProperty("ruleIds", out var list) || list.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var ids = new List<string>();
        foreach (var entry in list.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || entry.GetString() is not { Length: > 0 } id)
            {
                continue;
            }

            if (ids.Count >= MaxRuleIds)
            {
                return null;
            }

            ids.Add(id.Length > MaxStringLength ? id[..MaxStringLength] : id);
        }

        return ids;
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
