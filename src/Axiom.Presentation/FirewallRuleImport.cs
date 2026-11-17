// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;

namespace Axiom.Presentation;

public sealed record FirewallRuleImportApplyPlan(
    IReadOnlyList<RuleSpec> Rules,
    IReadOnlyList<string> Conflicts);

public sealed record FirewallRuleImportError(int Index, string Message);

/// <summary>
/// Result of reading and validating an exported rule file. The preview never applies, imports or
/// changes a rule; it only reports what would be valid.
/// </summary>
public sealed record FirewallRuleImportResult(
    bool SchemaValid,
    string? FileError,
    IReadOnlyList<RuleSpec> Rules,
    IReadOnlyList<FirewallRuleImportError> RuleErrors)
{
    public bool HasErrors => FileError is not null || RuleErrors.Count > 0;

    public int InvalidRuleCount => RuleErrors.Select(error => error.Index).Distinct().Count();
}

/// <summary>
/// Read-only preview of an exported firewall rule file (FND-008, import half). It checks the
/// schema and every rule with the same <see cref="RuleSpecValidator"/> the write path uses, then
/// reports the result. Applying an imported rule stays a separate, explicit action.
/// </summary>
public static class FirewallRuleImport
{
    public const int MaxCharacters = 4 * 1024 * 1024;

    public const int MaxRules = 1000;

    public static FirewallRuleImportResult Preview(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Invalid("The file is empty.");
        }

        if (json.Length > MaxCharacters)
        {
            return Invalid($"The file is larger than {MaxCharacters / (1024 * 1024)} MB.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException exception)
        {
            return Invalid("The file is not valid JSON: " + exception.Message);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Invalid("The file must contain a JSON object.");
            }

            var schema = root.TryGetProperty("schema", out var schemaElement) &&
                         schemaElement.ValueKind == JsonValueKind.String
                ? schemaElement.GetString()
                : null;
            if (!string.Equals(schema, FirewallRuleExport.Schema, StringComparison.Ordinal))
            {
                return Invalid(
                    $"Unsupported schema '{schema ?? "(missing)"}'. Expected '{FirewallRuleExport.Schema}'.");
            }

            if (!root.TryGetProperty("rules", out var rulesElement) || rulesElement.ValueKind != JsonValueKind.Array)
            {
                return Invalid("The file has no 'rules' array.");
            }

            var rules = new List<RuleSpec>();
            var errors = new List<FirewallRuleImportError>();
            var index = 0;
            foreach (var element in rulesElement.EnumerateArray())
            {
                if (index >= MaxRules)
                {
                    errors.Add(new FirewallRuleImportError(index, $"Only the first {MaxRules} rules are checked."));
                    break;
                }

                var spec = TryBuildSpec(element, index, out var message);
                if (spec is null)
                {
                    errors.Add(new FirewallRuleImportError(index, message));
                }
                else
                {
                    var validation = RuleSpecValidator.Validate(spec);
                    if (validation.IsValid)
                    {
                        rules.Add(spec);
                    }
                    else
                    {
                        errors.Add(new FirewallRuleImportError(
                            index,
                            string.Join("; ", validation.Errors.Select(error => error.Message))));
                    }
                }

                index++;
            }

            return new FirewallRuleImportResult(true, null, rules, errors);
        }
    }

    /// <summary>
    /// Builds the write plan for the valid rules: one Axiom identity per (path, direction), the
    /// imported scope, and this operator as the creator. Rules that would collapse onto the same
    /// identity with different actions are reported as conflicts and left out.
    /// </summary>
    public static FirewallRuleImportApplyPlan PlanApply(
        IReadOnlyList<RuleSpec> rules,
        string createdBy,
        string sourceLabel)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (string.IsNullOrWhiteSpace(createdBy))
        {
            throw new ArgumentException("A creator identity is required.", nameof(createdBy));
        }

        var planned = new List<RuleSpec>();
        var conflicts = new List<string>();
        var byIdentity = new Dictionary<(string Path, FirewallDirection Direction), RuleSpec>();

        foreach (var rule in rules)
        {
            var path = rule.AppPath.Trim();
            var key = (path.ToUpperInvariant(), rule.Direction);
            if (byIdentity.TryGetValue(key, out var existing))
            {
                if (existing.Action != rule.Action)
                {
                    conflicts.Add(
                        $"{path} ({rule.Direction}) appears with both {existing.Action} and {rule.Action}; only one action per application and direction is possible.");
                    continue;
                }

                continue;
            }

            var spec = new RuleSpec
            {
                ManagedRuleId = RuleIdentity.ForApp(path, rule.Direction),
                AppPath = path,
                Direction = rule.Direction,
                Action = rule.Action,
                Profiles = rule.Profiles,
                Protocol = rule.Protocol,
                RemoteAddresses = rule.RemoteAddresses,
                RemotePorts = rule.RemotePorts,
                Enabled = rule.Enabled,
                Description = string.IsNullOrWhiteSpace(sourceLabel)
                    ? "Imported Axiom rule"
                    : $"Imported Axiom rule from {sourceLabel}",
                CreatedBy = createdBy,
            };

            byIdentity[key] = spec;
            planned.Add(spec);
        }

        return new FirewallRuleImportApplyPlan(planned, conflicts);
    }

    private static FirewallRuleImportResult Invalid(string message) =>
        new(false, message, [], []);

    private static RuleSpec? TryBuildSpec(JsonElement element, int index, out string message)
    {
        message = string.Empty;
        if (element.ValueKind != JsonValueKind.Object)
        {
            message = "A rule entry must be an object.";
            return null;
        }

        if (!TryGetString(element, "managedRuleId", out var idText) || !Guid.TryParse(idText, out var id))
        {
            message = "managedRuleId is missing or not a GUID.";
            return null;
        }

        if (!TryGetString(element, "appPath", out var appPath) || string.IsNullOrWhiteSpace(appPath))
        {
            message = "appPath is missing.";
            return null;
        }

        if (!TryGetEnum<FirewallDirection>(element, "direction", out var direction))
        {
            message = "direction is missing or not Outbound/Inbound.";
            return null;
        }

        if (!TryGetEnum<FirewallAction>(element, "action", out var action))
        {
            message = "action is missing or not Block/Allow.";
            return null;
        }

        var profiles = FirewallProfile.All;
        if (element.TryGetProperty("profiles", out _) &&
            !TryGetEnum(element, "profiles", out profiles))
        {
            message = "profiles is not a combination of Domain/Private/Public/All/None.";
            return null;
        }

        var protocol = NetworkProtocol.Any;
        if (element.TryGetProperty("protocol", out _) &&
            !TryGetEnum(element, "protocol", out protocol))
        {
            message = "protocol is not Any/Tcp/Udp.";
            return null;
        }

        var addresses = new List<string>();
        if (element.TryGetProperty("remoteAddresses", out var addressElement) &&
            addressElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var address in addressElement.EnumerateArray())
            {
                if (address.ValueKind != JsonValueKind.String)
                {
                    message = "remoteAddresses must contain strings only.";
                    return null;
                }

                addresses.Add(address.GetString() ?? string.Empty);
            }
        }
        else if (element.TryGetProperty("remoteAddresses", out addressElement) &&
                 addressElement.ValueKind != JsonValueKind.Null)
        {
            message = "remoteAddresses must be an array.";
            return null;
        }

        var ports = TryGetString(element, "remotePorts", out var portText) && !string.IsNullOrWhiteSpace(portText)
            ? portText
            : null;
        var enabled = !element.TryGetProperty("enabled", out var enabledElement) ||
                      enabledElement.ValueKind == JsonValueKind.True ||
                      (enabledElement.ValueKind == JsonValueKind.False ? false : true);
        if (element.TryGetProperty("enabled", out enabledElement) &&
            enabledElement.ValueKind != JsonValueKind.True &&
            enabledElement.ValueKind != JsonValueKind.False)
        {
            message = "enabled must be true or false.";
            return null;
        }

        var description = TryGetString(element, "description", out var descriptionText)
            ? descriptionText
            : null;
        var createdBy = TryGetString(element, "createdBy", out var createdByText) && !string.IsNullOrWhiteSpace(createdByText)
            ? createdByText
            : "import-preview";
        var schemaVersion = RuleSpecSchema.CurrentVersion;
        if (element.TryGetProperty("schemaVersion", out var versionElement) &&
            versionElement.ValueKind == JsonValueKind.Number &&
            versionElement.TryGetInt32(out var parsedVersion))
        {
            schemaVersion = parsedVersion;
        }

        return new RuleSpec
        {
            ManagedRuleId = id,
            AppPath = appPath,
            Direction = direction,
            Action = action,
            Profiles = profiles,
            Protocol = protocol,
            RemoteAddresses = addresses,
            RemotePorts = ports,
            Enabled = enabled,
            Description = description,
            CreatedBy = createdBy,
            SchemaVersion = schemaVersion,
        };
    }

    private static bool TryGetString(JsonElement element, string name, out string value)
    {
        if (element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String)
        {
            value = property.GetString() ?? string.Empty;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryGetEnum<TEnum>(JsonElement element, string name, out TEnum value)
        where TEnum : struct, Enum
    {
        // Flags values such as "Private, Public" are valid but fail Enum.IsDefined, so the
        // RuleSpecValidator checks the individual bits instead.
        if (element.TryGetProperty(name, out var property) &&
            property.ValueKind == JsonValueKind.String &&
            Enum.TryParse(property.GetString(), ignoreCase: true, out value))
        {
            return true;
        }

        value = default;
        return false;
    }
}
