// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Firewall;

namespace Axiom.Infrastructure.Unix.Filter;

/// <summary>
/// One rule of the AxiomFilter rule table (docs/MACOS_ARCHITECTURE.md section 3.1). Property names
/// and string values are the wire contract with the Swift system extension.
/// </summary>
public sealed record FilterRule
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("appPath")]
    public string AppPath { get; init; } = string.Empty;

    /// <summary><c>outbound</c> | <c>inbound</c>.</summary>
    [JsonPropertyName("direction")]
    public required string Direction { get; init; }

    /// <summary><c>block</c> | <c>allow</c>.</summary>
    [JsonPropertyName("action")]
    public required string Action { get; init; }

    /// <summary><c>any</c> | <c>tcp</c> | <c>udp</c> | <c>icmp</c>.</summary>
    [JsonPropertyName("protocol")]
    public string Protocol { get; init; } = FilterRuleTable.ProtocolAny;

    [JsonPropertyName("remoteAddresses")]
    public IReadOnlyList<string> RemoteAddresses { get; init; } = [];

    [JsonPropertyName("remotePorts")]
    public string? RemotePorts { get; init; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    /// <summary>Field-wise equality (the record's list member compares by reference).</summary>
    public bool SameAs(FilterRule? other) =>
        other is not null &&
        string.Equals(Id, other.Id, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(AppPath, other.AppPath, StringComparison.Ordinal) &&
        string.Equals(Direction, other.Direction, StringComparison.Ordinal) &&
        string.Equals(Action, other.Action, StringComparison.Ordinal) &&
        string.Equals(Protocol, other.Protocol, StringComparison.Ordinal) &&
        RemoteAddresses.SequenceEqual(other.RemoteAddresses, StringComparer.OrdinalIgnoreCase) &&
        string.Equals(
            string.IsNullOrWhiteSpace(RemotePorts) ? null : RemotePorts.Trim(),
            string.IsNullOrWhiteSpace(other.RemotePorts) ? null : other.RemotePorts.Trim(),
            StringComparison.Ordinal) &&
        Enabled == other.Enabled;
}

/// <summary>The complete rules.json document.</summary>
public sealed record FilterRuleTable
{
    public const int CurrentSchemaVersion = 1;

    public const string DirectionOutbound = "outbound";

    public const string DirectionInbound = "inbound";

    public const string ActionBlock = "block";

    public const string ActionAllow = "allow";

    public const string ProtocolAny = "any";

    public const string ProtocolTcp = "tcp";

    public const string ProtocolUdp = "udp";

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    [JsonPropertyName("generation")]
    public long Generation { get; init; }

    /// <summary>The filter allows everything when it has no valid table (first start).</summary>
    [JsonPropertyName("failOpen")]
    public bool FailOpen { get; init; } = true;

    [JsonPropertyName("rules")]
    public IReadOnlyList<FilterRule> Rules { get; init; } = [];

    /// <summary>Maps an owned Axiom rule to its filter representation.</summary>
    public static FilterRule ToFilterRule(RuleSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);

        return new FilterRule
        {
            Id = spec.ManagedRuleId.ToString("D", CultureInfo.InvariantCulture),
            AppPath = spec.AppPath.Trim(),
            Direction = spec.Direction == FirewallDirection.Inbound ? DirectionInbound : DirectionOutbound,
            Action = spec.Action == FirewallAction.Block ? ActionBlock : ActionAllow,
            Protocol = spec.Protocol switch
            {
                NetworkProtocol.Tcp => ProtocolTcp,
                NetworkProtocol.Udp => ProtocolUdp,
                _ => ProtocolAny,
            },
            RemoteAddresses = (spec.RemoteAddresses ?? [])
                .Where(address => !string.IsNullOrWhiteSpace(address))
                .Select(address => address.Trim())
                .ToArray(),
            RemotePorts = string.IsNullOrWhiteSpace(spec.RemotePorts) ? null : spec.RemotePorts.Trim(),
            Enabled = spec.Enabled,
        };
    }

    /// <summary>Builds the table for <paramref name="specs"/>, ordered by id for stable diffs.</summary>
    public static FilterRuleTable Create(IEnumerable<RuleSpec> specs, long generation)
    {
        ArgumentNullException.ThrowIfNull(specs);

        return new FilterRuleTable
        {
            Generation = generation,
            Rules = specs
                .Select(ToFilterRule)
                .OrderBy(rule => rule.Id, StringComparer.Ordinal)
                .ToArray(),
        };
    }

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static FilterRuleTable? TryParse(string json)
    {
        try
        {
            var table = JsonSerializer.Deserialize<FilterRuleTable>(json, JsonOptions);
            return table is { SchemaVersion: CurrentSchemaVersion } ? table : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
