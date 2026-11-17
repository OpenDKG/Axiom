// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;

namespace Axiom.Presentation;

/// <summary>Strongest enforcement channel proven for the running build.</summary>
public enum EnforcementVerification
{
    /// <summary>Axiom can only ask the host to deny; no side effect has been proven.</summary>
    Cooperative = 0,

    /// <summary>A supported host refused a live canary call and the side effect was absent.</summary>
    HostDenyVerified = 1,

    /// <summary>An OS boundary refused direct access, not just a cooperative hook.</summary>
    OsBoundaryVerified = 2,
}

/// <summary>
/// Coarse protection level: green protected, orange degraded, red unprotected, grey unknown
/// (no authority answered, so nothing may be claimed either way).
/// </summary>
public enum EnforcementLevel
{
    Protected = 0,
    Degraded = 1,
    Unprotected = 2,
    Unknown = 3,
}

/// <summary>
/// What the Agents page may say about enforcement right now. The default state is cooperative:
/// detector signals are advisory and the UI is not allowed to advertise a verified block.
/// </summary>
public sealed record EnforcementSurfaceState
{
    public required EnforcementVerification Verification { get; init; }

    /// <summary>Short badge text, deliberately explicit that nothing is verified.</summary>
    public required string VerificationLabel { get; init; }

    public required string Summary { get; init; }

    public required string DetectorDetail { get; init; }

    public required string BrokerDetail { get; init; }

    public required string PolicyDetail { get; init; }

    /// <summary>
    /// True only when a live host or OS boundary has been proven. A cooperative hook, an installed
    /// file or a unit test can never satisfy this.
    /// </summary>
    public bool CanClaimVerifiedBlocking => Verification != EnforcementVerification.Cooperative;

    /// <summary>Coarse protection level used for the colour of the enforcement panel.</summary>
    public EnforcementLevel Level
    {
        get
        {
            if (VerificationLabel.Contains("NOT PROTECTED", StringComparison.OrdinalIgnoreCase) ||
                VerificationLabel.Contains("POLICY INVALID", StringComparison.OrdinalIgnoreCase))
            {
                return EnforcementLevel.Unprotected;
            }

            if (Verification != EnforcementVerification.Cooperative ||
                VerificationLabel.Contains("HOOK BLOCKING ACTIVE", StringComparison.OrdinalIgnoreCase))
            {
                return EnforcementLevel.Protected;
            }

            return EnforcementLevel.Degraded;
        }
    }

    /// <summary>Short label for compact surfaces such as Mini mode.</summary>
    public string LevelText => Level switch
    {
        EnforcementLevel.Protected => "Protected",
        EnforcementLevel.Degraded => "Degraded",
        EnforcementLevel.Unknown => "Unknown",
        _ => "Not protected",
    };

    public bool IsProtected => Level == EnforcementLevel.Protected;

    public bool IsDegraded => Level == EnforcementLevel.Degraded;

    public bool IsUnprotected => Level == EnforcementLevel.Unprotected;

    /// <summary>Current, honest state of this build.</summary>
    public static EnforcementSurfaceState Current { get; } = new()
    {
        Verification = EnforcementVerification.Cooperative,
        VerificationLabel = "COOPERATIVE - NOT VERIFIED",
        Summary = "Detector signals are advisory; no host deny has been verified on this build.",
        DetectorDetail =
            "Blackbox guard: detector only. A block verdict is a request, not a proven side effect.",
        BrokerDetail =
            "Managed runner and file broker: prototype only (ADR 0012, E3); blocking uses the host hooks, not the broker.",
        PolicyDetail =
            "Offline policy engine: available in the library, not wired to the hooks yet.",
    };

    /// <summary>
    /// Computes an honest <see cref="EnforcementSurfaceState"/> from live controller status and
    /// receipt evidence without ever promoting <c>HOST_DENY_SENT</c> to verified blocking.
    /// </summary>
    public static EnforcementSurfaceState FromReceiptsAndStatus(
        EnforcementStatusDto? status,
        EnforcementReceiptsSnapshotDto? receipts = null,
        bool guardAvailable = true,
        string? hostHookMode = null,
        int hostHookDenyCount = 0)
    {
        if (!guardAvailable)
        {
            return Current with
            {
                Verification = EnforcementVerification.Cooperative,
                VerificationLabel = "UNAVAILABLE - NOT PROTECTED",
                Summary = "Blackbox guard or required protection state is unavailable; actions are unprotected.",
                DetectorDetail = "Blackbox guard: UNAVAILABLE (guard could not be reached or ruleset is empty).",
            };
        }

        var osVerifiedCount = receipts?.Receipts.Count(r =>
            string.Equals(r.Result, "OS_DENY_VERIFIED", StringComparison.Ordinal)) ?? 0;
        var hostVerifiedCount = Math.Max(
            status?.HostDenyVerifiedCount ?? 0,
            receipts?.Receipts.Count(r =>
                string.Equals(r.Result, "HOST_DENY_VERIFIED", StringComparison.Ordinal)) ?? 0);
        var hostSentCount = Math.Max(
            status?.HostDenySentCount ?? 0,
            receipts?.Receipts.Count(r =>
                string.Equals(r.Result, "HOST_DENY_SENT", StringComparison.Ordinal)) ?? 0);
        var detectorDetail = FormatDetectorDetail(hostHookMode, hostSentCount, hostHookDenyCount);

        if (status?.Error is { Length: > 0 } error)
        {
            return Current with
            {
                Verification = EnforcementVerification.Cooperative,
                VerificationLabel = "POLICY INVALID - NOT VERIFIED",
                Summary = "Local enforcement policy failed validation and remains disabled.",
                DetectorDetail = detectorDetail,
                PolicyDetail = $"Offline policy engine error: {error}",
            };
        }

        if (osVerifiedCount > 0)
        {
            return Current with
            {
                Verification = EnforcementVerification.OsBoundaryVerified,
                VerificationLabel = "OS_BOUNDARY_VERIFIED",
                Summary = $"OS boundary refused direct action with absent side effect ({osVerifiedCount} verified receipt(s)).",
                DetectorDetail = detectorDetail,
                PolicyDetail = FormatPolicyDetail(status),
            };
        }

        if (hostVerifiedCount > 0)
        {
            return Current with
            {
                Verification = EnforcementVerification.HostDenyVerified,
                VerificationLabel = "HOST_DENY_VERIFIED (CANARY)",
                Summary = $"Disposable canary confirmed host hook blocked action with absent side effect ({hostVerifiedCount} verified receipt(s)).",
                DetectorDetail = detectorDetail,
                PolicyDetail = FormatPolicyDetail(status),
            };
        }

        if (hostSentCount > 0)
        {
            return Current with
            {
                Verification = EnforcementVerification.Cooperative,
                VerificationLabel = "HOST_DENY_SENT - NOT VERIFIED",
                Summary = $"Host deny payload was returned ({hostSentCount} receipt(s)), but no side-effect verification canary has passed.",
                DetectorDetail = detectorDetail,
                PolicyDetail = FormatPolicyDetail(status),
            };
        }

        if (status?.Enabled == true)
        {
            if (string.Equals(hostHookMode, "audit", StringComparison.OrdinalIgnoreCase))
            {
                return Current with
                {
                    VerificationLabel = "AUDIT MODE - NOT PROTECTED",
                    Summary =
                        "Blackbox hooks are in audit mode: agent actions are recorded but not blocked. Switch Blackbox to Block.",
                    DetectorDetail = detectorDetail,
                    PolicyDetail = FormatPolicyDetail(status),
                };
            }

            if (!string.Equals(hostHookMode, "block", StringComparison.OrdinalIgnoreCase))
            {
                return Current with
                {
                    VerificationLabel = "HOOK MODE UNKNOWN - NOT VERIFIED",
                    Summary =
                        "The enforcement policy is loaded, but the guard hook mode could not be read; blocking is not proven.",
                    DetectorDetail = detectorDetail,
                    PolicyDetail = FormatPolicyDetail(status),
                };
            }

            // The policy is loaded and the guard hooks return block verdicts; the missing piece is
            // a host/OS deny receipt, not the blocking itself. Say that instead of "advisory".
            return Current with
            {
                VerificationLabel = "HOOK BLOCKING ACTIVE",
                Summary =
                    "Guard hooks block protected reads, writes and credential stores; no host or OS deny receipt has been recorded yet.",
                DetectorDetail = detectorDetail,
                BrokerDetail = Current.BrokerDetail,
                PolicyDetail = FormatPolicyDetail(status),
            };
        }

        return Current with
        {
            DetectorDetail = detectorDetail,
            PolicyDetail = FormatPolicyDetail(status),
        };
    }

    private static string FormatDetectorDetail(string? hostHookMode, int hostSentCount, int hostHookDenyCount)
    {
        var hookSuffix = hostHookDenyCount > 0
            ? $" ({hostHookDenyCount} recent hook block(s))"
            : hostSentCount > 0
                ? $" ({hostSentCount} controller deny receipt(s))"
                : string.Empty;

        if (string.Equals(hostHookMode, "block", StringComparison.OrdinalIgnoreCase))
        {
            return $"Blackbox hooks (mode: block): active — protected reads/writes are refused (self-test passes){hookSuffix}; kernel/WFP deny is not enabled on this build.";
        }

        if (string.Equals(hostHookMode, "audit", StringComparison.OrdinalIgnoreCase))
        {
            return $"Blackbox hooks (mode: audit): monitoring only — switch Blackbox to Block below so agent hooks return deny verdicts{hookSuffix}.";
        }

        return Current.DetectorDetail;
    }

    private static string FormatPolicyDetail(EnforcementStatusDto? status)
    {
        if (status is null)
        {
            return Current.PolicyDetail;
        }

        return status.Enabled
            ? $"Offline policy engine: enabled (revision {status.Revision}, {status.RuleCount} rule(s), {status.ReceiptCount} receipt(s))."
            : $"Offline policy engine: disabled by default ({status.ReceiptCount} receipt(s)).";
    }
}
