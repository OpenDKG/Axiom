// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using Axiom.Contracts;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;

namespace Axiom.Infrastructure.Windows.Firewall;

/// <summary>
/// Windows Firewall policy adapter using the documented INetFwPolicy2/INetFwRule COM objects.
/// <para>
/// Read operations (capabilities, owned-rule listing, verification) are safe and need no admin on
/// a normal host. Write operations are refused unless BOTH environment variables are present:
/// <c>AXIOM_ENABLE_FIREWALL_WRITES=1</c> and <c>AXIOM_FIREWALL_WRITE_CONFIRM=yes</c>.
/// They are also limited to exact <c>Axiom::{id}::{OUT|IN}</c> rule names; no wildcard deletion
/// is possible. The product does not call them on a production workstation.
/// </para>
/// </summary>
public sealed class WindowsFirewallPolicyAdapter : IFirewallPolicyAdapter, IOwnedRuleRecoveryAdapter, IDisposable
{
    public const string WriteEnableVariable = FirewallWriteGate.WriteEnableVariable;

    public const string WriteConfirmVariable = FirewallWriteGate.WriteConfirmVariable;

    private const int NetFwActionBlock = 0;

    private const int NetFwActionAllow = 1;

    private const int NetFwDirectionIn = 1;

    private const int NetFwDirectionOut = 2;

    private const int NetFwProtocolTcp = 6;

    private const int NetFwProtocolUdp = 17;

    private const int NetFwProtocolAny = 256;

    // Firewall COM identities may be shared across adapter instances. Keep their calls in one
    // process-lifetime STA so disposing an adapter cannot tear down an apartment another uses.
    private static readonly Lazy<StaComExecutor> Com = new();
    private volatile bool _disposed;

    public Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct) =>
        InvokeComAsync(ProbeCapabilities, ct);

    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct) =>
        InvokeComAsync(ReadOwnedRules, ct);

    public Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        EnsureWriteGate();
        return InvokeComAsync(() => ApplyRule(spec), ct);
    }

    public Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        EnsureWriteGate();
        return InvokeComAsync(() => RemoveRule(managedRuleId), ct);
    }

    public Task<EffectiveRuleReport> VerifyAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ManagedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(spec));
        }

        return InvokeComAsync(() => VerifyRule(spec), ct);
    }

    /// <summary>
    /// Recovery-only inspection. No write gate is checked here: the service and the explicit
    /// administrator recovery command authorize the call, and this method only reports whether the
    /// exact identity still carries Axiom ownership metadata.
    /// </summary>
    public Task<OwnedRulePresence> InspectOwnedRuleAsync(
        Guid managedRuleId,
        FirewallDirection direction,
        CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        return InvokeComAsync(() => InspectCapturedRule(managedRuleId, direction), ct);
    }

    /// <summary>
    /// Recovery-only removal of one captured rule in one direction. It removes the exact
    /// <c>Axiom::{id}::{OUT|IN}</c> name (or its legacy equivalent) and refuses when the ownership
    /// metadata no longer matches. It never removes a rule by prefix or display name.
    /// </summary>
    public Task<RuleApplyResult> RemoveCapturedOwnedRuleAsync(
        Guid managedRuleId,
        FirewallDirection direction,
        CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        EnsureRecoveryWriteAllowed();
        return InvokeComAsync(() => RemoveCapturedRule(managedRuleId, direction), ct);
    }

    /// <summary>
    /// The recovery removal is not behind the interactive write gate because it must work while
    /// the shield is off, but it is still refused outside the non-interactive service or an
    /// explicitly elevated administrator process.
    /// </summary>
    private static void EnsureRecoveryWriteAllowed()
    {
        if (ProtectionWriteConsent.IsServiceHost)
        {
            return;
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        if (new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
        {
            return;
        }

        throw new NotSupportedException(
            "Network recovery writes require the elevated Axiom service or an administrator command.");
    }

    public void Dispose() => _disposed = true;

    private Task<T> InvokeComAsync<T>(Func<T> action, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Com.Value.InvokeAsync(action, cancellationToken);
    }

    /// <summary>
    /// True when the test override is present, or when the elevated service holds persisted user
    /// consent for the shield. An interactive process never writes: only the service can.
    /// </summary>
    public static bool IsWriteGateOpen => FirewallWriteGate.IsOpen;

    /// <summary>Explicit test/debug override; both variables must be present.</summary>
    public static bool EnvironmentGateOpen => FirewallWriteGate.EnvironmentGateOpen;

    private static void EnsureWriteGate()
    {
        if (!IsWriteGateOpen)
        {
            throw new NotSupportedException(
                ProtectionWriteConsent.Granted
                    ? "Firewall writes require the elevated Axiom service. Start it as a Windows service."
                    : $"Firewall writes are disabled. Enable Axiom Shield in the app, or set " +
                      $"{WriteEnableVariable}=1 and {WriteConfirmVariable}=yes on an isolated test VM.");
        }
    }

    private static dynamic CreatePolicy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new InvalidOperationException("Windows Firewall COM policy is not available."))
        ?? throw new InvalidOperationException("Windows Firewall COM policy could not be created.");

    private static FirewallCapabilityReport ProbeCapabilities()
    {
        try
        {
            var policy = CreatePolicy();
            var domain = (bool)policy.FirewallEnabled(1);
            var privateProfile = (bool)policy.FirewallEnabled(2);
            var publicProfile = (bool)policy.FirewallEnabled(4);
            var owned = CountOwnedRules(policy);

            return new FirewallCapabilityReport
            {
                Status = FirewallCapabilityStatus.Available,
                Reason = domain || privateProfile || publicProfile
                    ? null
                    : "Windows Firewall is disabled for every profile.",
                FirewallServiceRunning = null,
                ManagedRulesReadable = true,
                ManagedRuleCount = owned,
            };
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            return new FirewallCapabilityReport
            {
                Status = FirewallCapabilityStatus.Unavailable,
                Reason = exception.Message,
                ManagedRulesReadable = false,
            };
        }
    }

    private static IReadOnlyList<ManagedRule> ReadOwnedRules()
    {
        var policy = CreatePolicy();
        var rules = new List<ManagedRule>();

        foreach (dynamic rule in policy.Rules)
        {
            var name = (string?)rule.Name;
            if (!OwnedRuleName.TryParse(name, out var id, out var direction))
            {
                continue;
            }

            rules.Add(ToManagedRule(rule, id, direction, name!));
        }

        return rules;
    }

    private static int CountOwnedRules(dynamic policy)
    {
        var count = 0;
        foreach (dynamic rule in policy.Rules)
        {
            if (OwnedRuleName.IsOwned((string?)rule.Name))
            {
                count++;
            }
        }

        return count;
    }

    private static ManagedRule ToManagedRule(dynamic rule, Guid id, FirewallDirection direction, string name)
    {
        var action = (int)rule.Action == NetFwActionBlock ? FirewallAction.Block : FirewallAction.Allow;
        var profiles = (FirewallProfile)(int)rule.Profiles & FirewallProfile.All;
        var protocol = (int)rule.Protocol switch
        {
            NetFwProtocolTcp => NetworkProtocol.Tcp,
            NetFwProtocolUdp => NetworkProtocol.Udp,
            _ => NetworkProtocol.Any,
        };

        return new ManagedRule
        {
            ManagedRuleId = id,
            OsRuleName = OwnedRuleName.ToDisplayName(name),
            State = RuleState.Applied,
            Spec = new RuleSpec
            {
                ManagedRuleId = id,
                AppPath = (string?)rule.ApplicationName ?? string.Empty,
                Direction = direction,
                Action = action,
                Profiles = profiles,
                Protocol = protocol,
                RemoteAddresses = SplitList((string?)rule.RemoteAddresses),
                RemotePorts = NormalizePorts((string?)rule.RemotePorts),
                Enabled = (bool)rule.Enabled,
                Description = (string?)rule.Description,
                CreatedBy = "windows-firewall",
            },
            OwnershipGroup = (string?)rule.Grouping,
            OwnershipDescription = (string?)rule.Description,
        };
    }

    private static RuleApplyResult ApplyRule(RuleSpec spec)
    {
        var validation = RuleSpecValidator.Validate(spec);
        if (!validation.IsValid)
        {
            return Failed(
                spec.ManagedRuleId,
                "rule.invalid",
                string.Join("; ", validation.Errors.Select(error => $"{error.Code}: {error.Message}")));
        }

        var name = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction);
        var policy = CreatePolicy();

        try
        {
            var existing = FindRule(policy, name);
            dynamic rule = existing ?? Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FwRule")
                    ?? throw new InvalidOperationException("Windows Firewall COM rule is not available."))!;

            ApplyFields(rule, spec, name);

            if (existing is null)
            {
                policy.Rules.Add(rule);
            }

            var readBack = FindRule(policy, name);
            if (readBack is null || !MatchesSpec(readBack, spec))
            {
                // A property that cannot be cleared in place (for example a stale port scope) is
                // fixed by rebuilding the Axiom-owned rule once rather than reporting a half-state.
                if (existing is not null)
                {
                    TryRemove(policy, name);
                    dynamic rebuilt = Activator.CreateInstance(
                        Type.GetTypeFromProgID("HNetCfg.FwRule")
                            ?? throw new InvalidOperationException("Windows Firewall COM rule is not available."))!;
                    ApplyFields(rebuilt, spec, name);
                    policy.Rules.Add(rebuilt);
                    readBack = FindRule(policy, name);
                }

                if (readBack is null || !MatchesSpec(readBack, spec))
                {
                    TryRemove(policy, name);
                    return Failed(spec.ManagedRuleId, "rule.verify_failed", "The OS rule did not read back as written.");
                }
            }

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = spec.ManagedRuleId,
                State = RuleState.Applied,
                OsRuleName = OwnedRuleName.ToDisplayName(name),
                VerifiedUtc = DateTimeOffset.UtcNow,
            };
        }
        catch (Exception exception) when (exception is COMException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
        {
            return Failed(spec.ManagedRuleId, "rule.apply_failed", exception.Message);
        }
    }

    private static RuleApplyResult RemoveRule(Guid managedRuleId)
    {
        var policy = CreatePolicy();

        foreach (var direction in new[] { FirewallDirection.Outbound, FirewallDirection.Inbound })
        {
            var name = OwnedRuleName.Create(managedRuleId, direction);
            var legacyName = OwnedRuleName.ToLegacyName(name);
            if (FindRule(policy, name) is null && FindRule(policy, legacyName) is null)
            {
                continue;
            }

            if (FindRule(policy, name) is not null)
            {
                try
                {
                    policy.Rules.Remove(name);
                }
                catch (COMException)
                {
                    // Read-back below reports failure if the rule is still present.
                }
            }

            if (FindRule(policy, legacyName) is not null)
            {
                try
                {
                    policy.Rules.Remove(legacyName);
                }
                catch (COMException)
                {
                    // The legacy rule may have disappeared during removal.
                }
            }

            if (FindRule(policy, name) is not null || FindRule(policy, legacyName) is not null)
            {
                return Failed(managedRuleId, "rule.remove_failed", $"Rule '{name}' is still present after removal.");
            }
        }

        return new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = managedRuleId,
            State = RuleState.Desired,
            VerifiedUtc = DateTimeOffset.UtcNow,
        };
    }

    private static OwnedRulePresence InspectCapturedRule(Guid managedRuleId, FirewallDirection direction)
    {
        var policy = CreatePolicy();
        return InspectCapturedRule(policy, managedRuleId, direction);
    }

    private static OwnedRulePresence InspectCapturedRule(
        dynamic policy,
        Guid managedRuleId,
        FirewallDirection direction)
    {
        var name = OwnedRuleName.Create(managedRuleId, direction);
        var legacyName = OwnedRuleName.ToLegacyName(name);
        var current = FindRule(policy, name) ?? FindRule(policy, legacyName);
        if (current is null)
        {
            return OwnedRulePresence.Absent;
        }

        dynamic rule = current;
        return OwnedRuleOwnership.HasOwnershipMetadata(
            (string?)rule.Grouping,
            (string?)rule.Description)
            ? OwnedRulePresence.Owned
            : OwnedRulePresence.ForeignOrChanged;
    }

    private static RuleApplyResult RemoveCapturedRule(Guid managedRuleId, FirewallDirection direction)
    {
        var policy = CreatePolicy();
        var name = OwnedRuleName.Create(managedRuleId, direction);
        var legacyName = OwnedRuleName.ToLegacyName(name);
        var found = false;

        foreach (var candidate in new[] { name, legacyName })
        {
            var current = FindRule(policy, candidate);
            if (current is null)
            {
                continue;
            }

            found = true;
            dynamic rule = current;
            if (!OwnedRuleOwnership.HasOwnershipMetadata(
                    (string?)rule.Grouping,
                    (string?)rule.Description))
            {
                return Failed(
                    managedRuleId,
                    "rule.not_owned",
                    "The rule identity exists but no longer carries Axiom ownership metadata.");
            }

            try
            {
                policy.Rules.Remove(candidate);
            }
            catch (COMException)
            {
                // A concurrent removal may have won; the read-back below decides.
            }
        }

        if (!found)
        {
            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Desired,
                VerifiedUtc = DateTimeOffset.UtcNow,
            };
        }

        if (FindRule(policy, name) is not null || FindRule(policy, legacyName) is not null)
        {
            return Failed(
                managedRuleId,
                "rule.remove_failed",
                $"Rule '{name}' is still present after recovery removal.");
        }

        return new RuleApplyResult
        {
            Success = true,
            ManagedRuleId = managedRuleId,
            State = RuleState.Desired,
            VerifiedUtc = DateTimeOffset.UtcNow,
        };
    }

    private static EffectiveRuleReport VerifyRule(RuleSpec spec)
    {
        var policy = CreatePolicy();
        var name = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction);
        var rule = FindRule(policy, name) ?? FindRule(policy, OwnedRuleName.ToLegacyName(name));
        if (rule is null)
        {
            return new EffectiveRuleReport
            {
                ManagedRuleId = spec.ManagedRuleId,
                PresentInOs = false,
                MatchesSpec = false,
                EffectiveAction = null,
                Notes = ["No owned rule with this id and direction is present in Windows Firewall."],
            };
        }

        var action = (int)rule.Action == NetFwActionBlock ? FirewallAction.Block : FirewallAction.Allow;
        var notes = new List<string>();
        if (action != spec.Action)
        {
            notes.Add("Action differs from the persisted specification.");
        }

        if (!MatchesSpec(rule, spec))
        {
            notes.Add("One or more enforcement fields differ from the persisted specification.");
        }

        return new EffectiveRuleReport
        {
            ManagedRuleId = spec.ManagedRuleId,
            PresentInOs = true,
            MatchesSpec = notes.Count == 0,
            EffectiveAction = action,
            Notes = notes,
        };
    }

    internal static void ApplyFields(dynamic rule, RuleSpec spec, string name)
    {
        SetField(() => rule.Name = name, "Name");
        SetField(() => rule.Description = spec.Description ?? $"Axiom managed rule {spec.ManagedRuleId:D}", "Description");
        SetField(() => rule.ApplicationName = spec.AppPath, "ApplicationName");
        SetField(
            () => rule.Direction = spec.Direction == FirewallDirection.Outbound ? NetFwDirectionOut : NetFwDirectionIn,
            "Direction");
        SetField(() => rule.Profiles = (int)spec.Profiles, "Profiles");
        SetField(() => rule.Action = spec.Action == FirewallAction.Block ? NetFwActionBlock : NetFwActionAllow, "Action");
        SetField(
            () => rule.Protocol = spec.Protocol switch
            {
                NetworkProtocol.Tcp => NetFwProtocolTcp,
                NetworkProtocol.Udp => NetFwProtocolUdp,
                _ => NetFwProtocolAny,
            },
            "Protocol");
        SetField(() => rule.Enabled = spec.Enabled, "Enabled");
        SetField(() => rule.Grouping = "Axiom", "Grouping");

        // The port scope is only meaningful for TCP/UDP. INetFwRule rejects a port string on the
        // "any protocol" rule (E_INVALIDARG), which is the default shape of a Shield block.
        // The port scope is only meaningful for TCP/UDP. INetFwRule rejects any RemotePorts value
        // while the protocol is "any" (ArgumentException / E_INVALIDARG), which is the default
        // shape of a Shield block, so the property is left at its empty default there.
        SetField(
            () => rule.RemoteAddresses = spec.RemoteAddresses.Count > 0
                ? string.Join(',', spec.RemoteAddresses)
                : "*",
            "RemoteAddresses");

        if (spec.Protocol != NetworkProtocol.Any)
        {
            SetField(
                () => rule.RemotePorts = string.IsNullOrWhiteSpace(spec.RemotePorts) ? "*" : spec.RemotePorts,
                "RemotePorts");
        }
    }

    private static void SetField(Action assignment, string field)
    {
        try
        {
            assignment();
        }
        catch (Exception exception) when (exception is COMException or ArgumentException)
        {
            throw new InvalidOperationException(
                $"Firewall rule field '{field}' was rejected: {exception.Message} (0x{exception.HResult:X8}).",
                exception);
        }
    }

    internal static bool MatchesSpec(dynamic rule, RuleSpec spec)
    {
        var expectedDirection = spec.Direction == FirewallDirection.Outbound
            ? NetFwDirectionOut
            : NetFwDirectionIn;
        var expectedProtocol = spec.Protocol switch
        {
            NetworkProtocol.Tcp => NetFwProtocolTcp,
            NetworkProtocol.Udp => NetFwProtocolUdp,
            _ => NetFwProtocolAny,
        };

        return string.Equals(
                OwnedRuleName.ToDisplayName((string?)rule.Name ?? string.Empty),
                OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction),
                StringComparison.Ordinal)
            && string.Equals((string?)rule.ApplicationName, spec.AppPath, StringComparison.OrdinalIgnoreCase)
            && (int)rule.Action == (spec.Action == FirewallAction.Block ? NetFwActionBlock : NetFwActionAllow)
            && (int)rule.Direction == expectedDirection
            && (int)rule.Protocol == expectedProtocol
            && (int)rule.Profiles == (int)spec.Profiles
            && (bool)rule.Enabled == spec.Enabled
            && AddressesMatch((string?)rule.RemoteAddresses, spec.RemoteAddresses)
            && PortsMatch(
                (string?)rule.RemotePorts,
                spec.Protocol == NetworkProtocol.Any ? null : spec.RemotePorts);
    }

    private static bool PortsMatch(string? actual, string? expected)
    {
        var actualValues = SplitList(actual)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var expectedValues = SplitList(expected)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return actualValues.SequenceEqual(expectedValues, StringComparer.OrdinalIgnoreCase);
    }

    private static bool AddressesMatch(string? actual, IReadOnlyList<string> expected)
    {
        var actualValues = SplitList(actual)
            .Select(value => NormalizeAddress(value) ?? value)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var expectedValues = expected
            .Select(value => NormalizeAddress(value) ?? value)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return actualValues.SequenceEqual(expectedValues, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Windows Firewall rewrites IPv4 CIDR to address/mask form ("1.0.0.0/8" reads back as
    /// "1.0.0.0/255.0.0.0") and bare host addresses as "/255.255.255.255" ("10.5.4.3" reads back
    /// as "10.5.4.3/255.255.255.255"). Host masks (/32 for IPv4, /128 for IPv6) reduce to the bare
    /// address and all other masks reduce to canonical network/prefix notation so read-back
    /// verification compares the effective scope rather than Windows COM formatting.
    /// </summary>
    internal static string? NormalizeAddress(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "*")
        {
            return null;
        }

        var slash = value.IndexOf('/');
        if (slash < 0)
        {
            return IPAddress.TryParse(value, out var single) ? single.ToString() : null;
        }

        if (!IPAddress.TryParse(value[..slash], out var address))
        {
            return null;
        }

        var suffix = value[(slash + 1)..];
        int prefix;

        if (suffix.Contains('.') || suffix.Contains(':'))
        {
            if (!IPAddress.TryParse(suffix, out var mask) ||
                mask.AddressFamily != address.AddressFamily)
            {
                return null;
            }

            prefix = CountBits(mask.GetAddressBytes());
        }
        else if (!int.TryParse(suffix, System.Globalization.NumberStyles.None,
                     System.Globalization.CultureInfo.InvariantCulture, out prefix))
        {
            return null;
        }

        var maxPrefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > maxPrefix)
        {
            return null;
        }

        var bytes = address.GetAddressBytes();
        var fullBytes = prefix / 8;
        var remaining = prefix % 8;

        for (var index = 0; index < bytes.Length; index++)
        {
            if (index < fullBytes)
            {
                continue;
            }

            if (index == fullBytes && remaining > 0)
            {
                bytes[index] &= (byte)(0xFF << (8 - remaining));
                continue;
            }

            bytes[index] = 0;
        }

        var network = new IPAddress(bytes);
        return prefix == maxPrefix
            ? network.ToString()
            : $"{network}/{prefix}";
    }

    private static int CountBits(byte[] mask)
    {
        var bits = 0;
        foreach (var value in mask)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                if ((value & (1 << bit)) != 0)
                {
                    bits++;
                }
            }
        }

        return bits;
    }

    private static object? FindRule(dynamic policy, string name)
    {
        foreach (dynamic rule in policy.Rules)
        {
            if (string.Equals((string?)rule.Name, name, StringComparison.Ordinal))
            {
                return rule;
            }
        }

        return null;
    }

    private static void TryRemove(dynamic policy, string name)
    {
        try
        {
            policy.Rules.Remove(name);
        }
        catch (COMException)
        {
            // Rollback is best effort; the caller already has a failure result.
        }
    }

    private static RuleApplyResult Failed(Guid id, string code, string message) => new()
    {
        Success = false,
        ManagedRuleId = id,
        State = RuleState.Failed,
        ErrorCode = code,
        ErrorMessage = message,
    };

    private static string[] SplitList(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "*")
        {
            return [];
        }

        return value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static string? NormalizePorts(string? value) =>
        string.IsNullOrWhiteSpace(value) || value == "*" ? null : value;
}
