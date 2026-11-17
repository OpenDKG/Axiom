// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// The network-protection lamp (header badge, Home, Mini) in the same vocabulary as the agent
/// enforcement surface: <see cref="EnforcementLevel"/>. One decision for every surface:
/// <list type="bullet">
/// <item><see cref="EnforcementLevel.Unknown"/> (grey): the service did not answer; nothing is claimed.</item>
/// <item><see cref="EnforcementLevel.Unprotected"/> (red): the service answered that protection is off.</item>
/// <item><see cref="EnforcementLevel.Degraded"/> (amber): protection is on but the enforcer has not
/// confirmed the published rules (macOS/Linux "blocks not verified").</item>
/// <item><see cref="EnforcementLevel.Protected"/> (green): on, and confirmed by the enforcer.</item>
/// </list>
/// A network-filter acknowledgement only proves the rules were loaded; it is never an
/// <c>OS_DENY_VERIFIED</c> receipt and never changes <see cref="EnforcementSurfaceState"/>.
/// </summary>
public static class ProtectionLamp
{
    public const string ProtectedColor = "#4ADE80";

    public const string DegradedColor = "#FBBF24";

    public const string UnprotectedColor = "#FB7185";

    public const string UnknownColor = "#94A3B8";

    /// <param name="answered">The service answered the latest protection query.</param>
    /// <param name="shieldOn">The answer says protection is on.</param>
    /// <param name="rulesConfirmed">The enforcer confirmed the current rules. Windows Firewall
    /// rules are read back synchronously by the service, so Windows callers pass true.</param>
    public static EnforcementLevel ForNetwork(bool answered, bool shieldOn, bool rulesConfirmed)
    {
        if (!answered)
        {
            return EnforcementLevel.Unknown;
        }

        if (!shieldOn)
        {
            return EnforcementLevel.Unprotected;
        }

        return rulesConfirmed ? EnforcementLevel.Protected : EnforcementLevel.Degraded;
    }

    public static string ColorFor(EnforcementLevel level) => level switch
    {
        EnforcementLevel.Protected => ProtectedColor,
        EnforcementLevel.Degraded => DegradedColor,
        EnforcementLevel.Unprotected => UnprotectedColor,
        _ => UnknownColor,
    };
}
