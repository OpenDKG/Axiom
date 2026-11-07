// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
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
public sealed class WindowsFirewallPolicyAdapter : IFirewallPolicyAdapter, IDisposable
{
    public const string WriteEnableVariable = "AXIOM_ENABLE_FIREWALL_WRITES";

    public const string WriteConfirmVariable = "AXIOM_FIREWALL_WRITE_CONFIRM";

    private const int NetFwActionBlock = 0;

    private const int NetFwActionAllow = 1;

    private const int NetFwDirectionIn = 1;

    private const int NetFwDirectionOut = 2;

    private const int NetFwProtocolTcp = 6;

    private const int NetFwProtocolUdp = 17;

    private const int NetFwProtocolAny = 256;

    private readonly StaComExecutor _com = new();

    public Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct) =>
        _com.InvokeAsync(ProbeCapabilities, ct);

    public Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct) =>
        _com.InvokeAsync(ReadOwnedRules, ct);

    public Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        EnsureWriteGate();
        return _com.InvokeAsync(() => ApplyRule(spec), ct);
    }

    public Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        EnsureWriteGate();
        return _com.InvokeAsync(() => RemoveRule(managedRuleId), ct);
    }

    public Task<EffectiveRuleReport> VerifyAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ManagedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(spec));
        }

        return _com.InvokeAsync(() => VerifyRule(spec), ct);
    }

    public void Dispose() => _com.Dispose();

    /// <summary>
    /// True when the test override is present, or when the elevated service holds persisted user
    /// consent for the shield. An interactive process never writes: only the service can.
    /// </summary>
    public static bool IsWriteGateOpen =>
        EnvironmentGateOpen ||
        (ProtectionWriteConsent.Granted && ProtectionWriteConsent.IsServiceHost);

    /// <summary>Explicit test/debug override; both variables must be present.</summary>
    public static bool EnvironmentGateOpen =>
        string.Equals(
            Environment.GetEnvironmentVariable(WriteEnableVariable)
            ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_ENABLE_FIREWALL_WRITES"),
            "1",
            StringComparison.Ordinal) &&
        string.Equals(
            Environment.GetEnvironmentVariable(WriteConfirmVariable)
            ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_FIREWALL_WRITE_CONFIRM"),
            "yes",
            StringComparison.OrdinalIgnoreCase);

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
                if (existing is null)
                {
                    TryRemove(policy, name);
                }

                return Failed(spec.ManagedRuleId, "rule.verify_failed", "The OS rule did not read back as written.");
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
        catch (Exception exception) when (exception is COMException or UnauthorizedAccessException or InvalidOperationException)
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
                policy.Rules.Remove(name);
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

    private static EffectiveRuleReport VerifyRule(RuleSpec spec)
    {
        var policy = CreatePolicy();
        var name = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction);
        var rule = FindRule(policy, name);
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
        rule.Name = name;
        rule.Description = spec.Description ?? $"Axiom managed rule {spec.ManagedRuleId:D}";
        rule.ApplicationName = spec.AppPath;
        rule.Direction = spec.Direction == FirewallDirection.Outbound ? NetFwDirectionOut : NetFwDirectionIn;
        rule.Action = spec.Action == FirewallAction.Block ? NetFwActionBlock : NetFwActionAllow;
        rule.Profiles = (int)spec.Profiles;
        rule.Protocol = spec.Protocol switch
        {
            NetworkProtocol.Tcp => NetFwProtocolTcp,
            NetworkProtocol.Udp => NetFwProtocolUdp,
            _ => NetFwProtocolAny,
        };

        if (spec.RemoteAddresses.Count > 0)
        {
            rule.RemoteAddresses = string.Join(',', spec.RemoteAddresses);
        }
        else
        {
            rule.RemoteAddresses = "*";
        }

        // Reusing an existing OS rule must actively clear a previous port restriction. Leaving the
        // property untouched would keep the old scope while reporting a successful update.
        rule.RemotePorts = !string.IsNullOrWhiteSpace(spec.RemotePorts) && spec.Protocol != NetworkProtocol.Any
            ? spec.RemotePorts
            : "*";

        rule.Enabled = spec.Enabled;
        rule.Grouping = "Axiom";
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

        return string.Equals((string?)rule.Name, OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction), StringComparison.Ordinal)
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
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var expectedValues = expected
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return actualValues.SequenceEqual(expectedValues, StringComparer.OrdinalIgnoreCase);
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
