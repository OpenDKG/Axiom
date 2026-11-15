// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Firewall;

namespace Axiom.Core.Firewall;

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

    public const int MaxRemoteAddresses = 32;

    public const int MaxRemotePortsLength = 256;

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
        ValidateRemoteAddresses(spec.RemoteAddresses, errors);
        ValidateRemotePorts(spec.RemotePorts, spec.Protocol, errors);

        return new RuleSpecValidationResult { IsValid = errors.Count == 0, Errors = errors };
    }

    private static void ValidateRemoteAddresses(
        IReadOnlyList<string>? addresses,
        List<RuleSpecValidationError> errors)
    {
        if (addresses is null)
        {
            errors.Add(new RuleSpecValidationError(
                "rule.addresses.missing",
                "Remote addresses must be an empty list or a list of IP addresses/CIDR ranges."));
            return;
        }

        if (addresses.Count == 0)
        {
            return;
        }

        if (addresses.Count > MaxRemoteAddresses)
        {
            errors.Add(new RuleSpecValidationError(
                "rule.addresses.too_many",
                $"At most {MaxRemoteAddresses} remote addresses are supported."));
            return;
        }

        var sawWildcard = false;

        foreach (var raw in addresses)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                errors.Add(new RuleSpecValidationError(
                    "rule.addresses.empty",
                    "Remote addresses must not contain an empty entry."));
                continue;
            }

            var value = raw.Trim();

            if (value == "*")
            {
                sawWildcard = true;
                continue;
            }

            if (value.Any(char.IsControl) || value.Contains(' '))
            {
                errors.Add(new RuleSpecValidationError(
                    "rule.addresses.invalid",
                    $"'{value}' is not an IP address or CIDR range."));
                continue;
            }

            if (!TryParseAddressOrCidr(value))
            {
                errors.Add(new RuleSpecValidationError(
                    "rule.addresses.invalid",
                    $"'{value}' is not an IP address or CIDR range."));
            }
        }

        if (sawWildcard && addresses.Count > 1)
        {
            errors.Add(new RuleSpecValidationError(
                "rule.addresses.any_mixed",
                "The wildcard '*' must be the only remote address."));
        }
    }

    private static void ValidateRemotePorts(
        string? ports,
        NetworkProtocol protocol,
        List<RuleSpecValidationError> errors)
    {
        if (string.IsNullOrWhiteSpace(ports))
        {
            return;
        }

        if (protocol == NetworkProtocol.Any)
        {
            errors.Add(new RuleSpecValidationError(
                "rule.ports.protocol_required",
                "Remote ports require the TCP or UDP protocol."));
            return;
        }

        if (ports.Length > MaxRemotePortsLength)
        {
            errors.Add(new RuleSpecValidationError(
                "rule.ports.too_long",
                $"Remote ports must be at most {MaxRemotePortsLength} characters."));
            return;
        }

        foreach (var raw in ports.Split(','))
        {
            var value = raw.Trim();

            if (value.Length == 0)
            {
                errors.Add(new RuleSpecValidationError(
                    "rule.ports.empty",
                    "Remote ports must not contain an empty entry."));
                continue;
            }

            var dash = value.IndexOf('-');

            if (dash < 0)
            {
                if (!TryParsePort(value, out _))
                {
                    errors.Add(new RuleSpecValidationError(
                        "rule.ports.invalid",
                        $"'{value}' is not a port between 1 and 65535."));
                }

                continue;
            }

            if (value.IndexOf('-', dash + 1) >= 0)
            {
                errors.Add(new RuleSpecValidationError(
                    "rule.ports.invalid",
                    $"'{value}' is not a valid port range."));
                continue;
            }

            var startText = value[..dash];
            var endText = value[(dash + 1)..];

            if (!TryParsePort(startText, out var start) ||
                !TryParsePort(endText, out var end) ||
                start > end)
            {
                errors.Add(new RuleSpecValidationError(
                    "rule.ports.invalid",
                    $"'{value}' is not a valid ascending port range."));
            }
        }
    }

    private static bool TryParseAddressOrCidr(string value)
    {
        var slash = value.IndexOf('/');

        if (slash < 0)
        {
            return IPAddress.TryParse(value, out _);
        }

        if (slash == 0 || slash == value.Length - 1)
        {
            return false;
        }

        var addressText = value[..slash];
        var prefixText = value[(slash + 1)..];

        if (!IPAddress.TryParse(addressText, out var address) ||
            !int.TryParse(prefixText, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
        {
            return false;
        }

        var maxPrefix = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => 32,
            AddressFamily.InterNetworkV6 => 128,
            _ => -1,
        };

        return maxPrefix > 0 && prefix >= 0 && prefix <= maxPrefix;
    }

    private static bool TryParsePort(string value, out int port) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out port) &&
        port is >= 1 and <= 65535;

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

        if (appPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // UNC and extended-length prefixes need a separate policy decision (FND-006). Checked
            // before the absolute test: on Linux a UNC path is not "fully qualified", which would
            // report the wrong reason and diverge from the Windows build.
            errors.Add(new RuleSpecValidationError("rule.path.unc_not_supported", "UNC and extended-length paths are not supported yet."));
            return;
        }

        if (!IsAbsolutePath(appPath))
        {
            errors.Add(new RuleSpecValidationError("rule.path.not_absolute", "Application path must be absolute."));
            return;
        }

        if (appPath.Split(PathSeparators, StringSplitOptions.RemoveEmptyEntries)
            .Any(segment => segment is ".." or "."))
        {
            errors.Add(new RuleSpecValidationError("rule.path.unstable_segment", "Application path must be fully normalised (no '.' or '..' segments)."));
        }
    }

    /// <summary>
    /// Absolute under the running OS or under Windows rules. <see cref="RuleSpec"/> models a
    /// Windows Firewall rule, and the Linux adapters reuse it, so validation must not depend on
    /// which separator the host prefers (Path.IsPathFullyQualified(@"C:\…") is false on Linux).
    /// </summary>
    private static bool IsAbsolutePath(string path) =>
        Path.IsPathFullyQualified(path) ||
        (path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && PathSeparators.Contains(path[2]));

    private static RuleSpecValidationResult Invalid(string code, string message) =>
        new() { IsValid = false, Errors = [new RuleSpecValidationError(code, message)] };
}
