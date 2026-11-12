// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;

namespace Axiom.Infrastructure.Unix.Filter;

/// <summary>The daemon's durable record of the rules it owns, with the generation of the last publication.</summary>
public sealed record ManagedRuleState
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public long Generation { get; init; }

    public IReadOnlyList<ManagedRule> Rules { get; init; } = [];
}

/// <summary>
/// <c>filter/managed-rules.json</c> (0600): the Unix equivalent of the Axiom-named Windows
/// Firewall rules. Every entry is Axiom-owned by construction; records written before the
/// recovery feature carry no ownership group and get the marker on load. Shared by the macOS
/// adapter (which also publishes <c>rules.json</c> for AxiomFilter) and the Linux adapter.
/// </summary>
public sealed class ManagedRuleStore
{
    private static readonly JsonSerializerOptions StateJson = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly string _path;

    public ManagedRuleStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    public string Path => _path;

    public ManagedRuleState Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new ManagedRuleState();
            }

            var state = JsonSerializer.Deserialize<ManagedRuleState>(File.ReadAllText(_path), StateJson);
            return state is { SchemaVersion: ManagedRuleState.CurrentSchemaVersion }
                ? state with
                {
                    Rules = (state.Rules ?? [])
                        .Where(rule => rule.ManagedRuleId != Guid.Empty)
                        .Select(rule => string.IsNullOrWhiteSpace(rule.OwnershipGroup)
                            ? rule with { OwnershipGroup = OwnedRuleOwnership.GroupName }
                            : rule)
                        .ToList(),
                }
                : new ManagedRuleState();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return new ManagedRuleState();
        }
    }

    public void Save(ManagedRuleState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        FilterRulesFile.WriteAtomic(_path, JsonSerializer.Serialize(state, StateJson) + "\n", FilterRulesFile.PrivateMode);
    }
}
