// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Firewall;

namespace Axiom.Presentation;

/// <summary>
/// Read-only JSON export of the Axiom-owned firewall rules (issue FND-008). It carries the durable
/// rule intent and the OS rule state so an operator can review or archive what Axiom owns; it never
/// includes secrets, raw exceptions or unrelated Windows rules.
/// </summary>
public static class FirewallRuleExport
{
    public const string Schema = "axiom.firewall-rules.v1";

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public static string ToJson(IEnumerable<ManagedRule> rules, DateTimeOffset exportedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var payload = new
        {
            schema = Schema,
            exportedAtUtc = exportedAtUtc.ToUniversalTime().ToString("O"),
            rules = rules.Select(rule => new
            {
                managedRuleId = rule.ManagedRuleId,
                osRuleName = rule.OsRuleName,
                state = rule.State.ToString(),
                lastVerifiedUtc = rule.LastVerifiedUtc?.ToUniversalTime().ToString("O"),
                lastErrorCode = rule.LastErrorCode,
                appPath = rule.Spec.AppPath,
                direction = rule.Spec.Direction.ToString(),
                action = rule.Spec.Action.ToString(),
                profiles = rule.Spec.Profiles.ToString(),
                protocol = rule.Spec.Protocol.ToString(),
                remoteAddresses = rule.Spec.RemoteAddresses,
                remotePorts = rule.Spec.RemotePorts,
                enabled = rule.Spec.Enabled,
                description = rule.Spec.Description,
                createdBy = rule.Spec.CreatedBy,
                schemaVersion = rule.Spec.SchemaVersion,
            }).ToArray(),
        };

        return JsonSerializer.Serialize(payload, Options);
    }
}
