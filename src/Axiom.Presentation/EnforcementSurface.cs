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

    /// <summary>Current, honest state of this build.</summary>
    public static EnforcementSurfaceState Current { get; } = new()
    {
        Verification = EnforcementVerification.Cooperative,
        VerificationLabel = "COOPERATIVE - NOT VERIFIED",
        Summary = "Detector signals are advisory; no host deny has been verified on this build.",
        DetectorDetail =
            "Blackbox guard: detector only. A block verdict is a request, not a proven side effect.",
        BrokerDetail =
            "Managed runner and file broker: not implemented (feasibility gate in ADR 0010).",
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
        bool guardAvailable = true)
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

        if (status?.Error is { Length: > 0 } error)
        {
            return Current with
            {
                Verification = EnforcementVerification.Cooperative,
                VerificationLabel = "POLICY INVALID - NOT VERIFIED",
                Summary = "Local enforcement policy failed validation and remains disabled.",
                PolicyDetail = $"Offline policy engine error: {error}",
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

        if (osVerifiedCount > 0)
        {
            return Current with
            {
                Verification = EnforcementVerification.OsBoundaryVerified,
                VerificationLabel = "OS_BOUNDARY_VERIFIED",
                Summary = $"OS boundary refused direct action with absent side effect ({osVerifiedCount} verified receipt(s)).",
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
                PolicyDetail = FormatPolicyDetail(status),
            };
        }

        return Current with
        {
            PolicyDetail = FormatPolicyDetail(status),
        };
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
