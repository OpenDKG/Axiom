// SPDX-License-Identifier: GPL-3.0-or-later
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
}
