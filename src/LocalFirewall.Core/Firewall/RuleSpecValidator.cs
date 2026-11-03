// SPDX-License-Identifier: GPL-3.0-or-later
using LocalFirewall.Contracts.Firewall;

namespace LocalFirewall.Core.Firewall;

public sealed record RuleSpecValidationError(string Code, string Message);

public sealed record RuleSpecValidationResult
{
    public required bool IsValid { get; init; }

    public required IReadOnlyList<RuleSpecValidationError> Errors { get; init; }
}

/// <summary>
/// Pure validation of <see cref="RuleSpec"/> before it may reach the OS adapter. No Windows API,
/// no I/O: this type runs identically on any platform and is unit tested.
/// </summary>
public static class RuleSpecValidator
{
    public const int MaxDescriptionLength = 512;

    public const int MaxPathLength = 4096;

    public const int MaxCreatedByLength = 256;

    private static readonly char[] PathSeparators = ['\\', '/'];

    public static RuleSpecValidationResult Validate(RuleSpec? spec)
    {
        if (spec is null)
        {
            return Invalid("rule.spec.missing", "Rule spec is required.");
        }

        var errors = new List<RuleSpecValidationError>();

        if (spec.ManagedRuleId == Guid.Empty)
        {
            errors.Add(new RuleSpecValidationError("rule.id.empty", "Managed rule id must not be empty."));
        }

        ValidatePath(spec.AppPath, errors);

        if (!Enum.IsDefined(spec.Direction))
        {
            errors.Add(new RuleSpecValidationError("rule.direction.undefined", "Direction is not a defined value."));
        }

        if (!Enum.IsDefined(spec.Action))
        {
            errors.Add(new RuleSpecValidationError("rule.action.undefined", "Action is not a defined value."));
        }

        if (!Enum.IsDefined(spec.Protocol))
        {
            errors.Add(new RuleSpecValidationError("rule.protocol.undefined", "Protocol is not a defined value."));
        }

        if (spec.Profiles == FirewallProfile.None)
        {
            errors.Add(new RuleSpecValidationError("rule.profiles.empty", "At least one network profile is required."));
        }
        else if ((spec.Profiles & ~FirewallProfile.All) != 0)
        {
            errors.Add(new RuleSpecValidationError("rule.profiles.invalid", "Profiles contain undefined bits."));
        }

        if (string.IsNullOrWhiteSpace(spec.CreatedBy))
        {
            errors.Add(new RuleSpecValidationError("rule.created_by.missing", "CreatedBy identity is required for the audit trail."));
        }
        else if (spec.CreatedBy.Length > MaxCreatedByLength)
        {
            errors.Add(new RuleSpecValidationError("rule.created_by.too_long", $"CreatedBy must be at most {MaxCreatedByLength} characters."));
        }

        if (spec.SchemaVersion != RuleSpecSchema.CurrentVersion)
        {
            errors.Add(new RuleSpecValidationError(
                "rule.schema.unsupported",
                $"Schema version {spec.SchemaVersion} is not supported (expected {RuleSpecSchema.CurrentVersion})."));
        }

        if (spec.Description is { Length: > MaxDescriptionLength })
        {
            errors.Add(new RuleSpecValidationError(
                "rule.description.too_long",
                $"Description must be at most {MaxDescriptionLength} characters."));
        }

        // Deferred by design: remote address/CIDR and port parsing is implemented with the
        // advanced rule scope in FND-008, together with its own tests and fuzzing.

        return new RuleSpecValidationResult { IsValid = errors.Count == 0, Errors = errors };
    }

    private static void ValidatePath(string? appPath, List<RuleSpecValidationError> errors)
    {
        if (string.IsNullOrWhiteSpace(appPath))
        {
            errors.Add(new RuleSpecValidationError("rule.path.missing", "Application path is required."));
            return;
        }

        if (appPath.Length > MaxPathLength)
        {
            errors.Add(new RuleSpecValidationError("rule.path.too_long", $"Application path must be at most {MaxPathLength} characters."));
            return;
        }

        if (appPath.Any(char.IsControl))
        {
            errors.Add(new RuleSpecValidationError("rule.path.control_character", "Application path contains control characters."));
            return;
        }

        if (!Path.IsPathFullyQualified(appPath))
        {
            errors.Add(new RuleSpecValidationError("rule.path.not_absolute", "Application path must be absolute."));
            return;
        }

        if (appPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // UNC and extended-length prefixes need a separate policy decision (FND-006).
            errors.Add(new RuleSpecValidationError("rule.path.unc_not_supported", "UNC and extended-length paths are not supported yet."));
            return;
        }

        if (appPath.Split(PathSeparators, StringSplitOptions.RemoveEmptyEntries)
            .Any(segment => segment is ".." or "."))
        {
            errors.Add(new RuleSpecValidationError("rule.path.unstable_segment", "Application path must be fully normalised (no '.' or '..' segments)."));
        }
    }

    private static RuleSpecValidationResult Invalid(string code, string message) =>
        new() { IsValid = false, Errors = [new RuleSpecValidationError(code, message)] };
}
