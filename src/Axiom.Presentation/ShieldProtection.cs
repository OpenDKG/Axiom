// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// One protection state for the firewall shield on every surface (header lamp, Simple home, Mini,
/// Firewall badge, Mini module health), in upstream's <see cref="EnforcementLevel"/> vocabulary
/// (1.0.0: Protected / Degraded / Not protected, tones ok / warn / fail) plus the one state the
/// shield has and the agent guard does not: the local service has not answered (unknown, the
/// neutral "idle" tone upstream uses for a module that is not connected).
/// </summary>
public static class ShieldProtection
{
    public const string UnknownColor = "#94A3B8";

    public const string ProtectedColor = "#4ADE80";

    public const string DegradedColor = "#FBBF24";

    public const string UnprotectedColor = "#FB7185";

    /// <summary>
    /// Level of the firewall shield. <c>null</c> means unknown: the service did not answer, so
    /// neither the last green nor a red claim may be shown.
    /// </summary>
    /// <param name="known">The service answered the latest protection probe.</param>
    /// <param name="enabled">Axiom Shield is on.</param>
    /// <param name="enforcementVerified">
    /// Whether the platform filter proved enforcement (Linux nft/BPF, macOS filter). <c>null</c>
    /// where the platform does not report it (Windows Firewall), which keeps upstream's green.
    /// </param>
    public static EnforcementLevel? Level(bool known, bool enabled, bool? enforcementVerified)
    {
        if (!known)
        {
            return null;
        }

        if (!enabled)
        {
            return EnforcementLevel.Unprotected;
        }

        return enforcementVerified == false ? EnforcementLevel.Degraded : EnforcementLevel.Protected;
    }

    /// <summary>Short label, same words as <see cref="EnforcementSurfaceState.LevelText"/>.</summary>
    public static string LevelText(EnforcementLevel? level) => level switch
    {
        null => "Unknown",
        EnforcementLevel.Protected => "Protected",
        EnforcementLevel.Degraded => "Degraded",
        _ => "Not protected",
    };

    /// <summary>
    /// <see cref="LevelText"/> for the shield, which says "Protected" only with a verified OS result.
    /// Where the platform reports none (Windows Firewall) it states what is known: the settings are on.
    /// </summary>
    public static string ShieldText(EnforcementLevel? level, bool? enforcementVerified) =>
        level == EnforcementLevel.Protected && enforcementVerified != true ? "Settings on" : LevelText(level);

    /// <summary>Tone class suffix used by the views: ok, warn, fail or idle (unknown).</summary>
    public static string Tone(EnforcementLevel? level) => level switch
    {
        null => "idle",
        EnforcementLevel.Protected => "ok",
        EnforcementLevel.Degraded => "warn",
        _ => "fail",
    };

    public static string LampColor(EnforcementLevel? level) => level switch
    {
        null => UnknownColor,
        EnforcementLevel.Protected => ProtectedColor,
        EnforcementLevel.Degraded => DegradedColor,
        _ => UnprotectedColor,
    };
}
