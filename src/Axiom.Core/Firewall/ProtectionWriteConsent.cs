// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Core.Firewall;

/// <summary>
/// Runtime consent for firewall writes. The service sets it from the persisted shield state; the
/// environment-variable gate in <see cref="FirewallWriteGate"/> stays as a test override.
/// Consent alone is not enough: writes are also refused in an interactive process, because only the
/// privileged service (Windows service / launchd daemon) can change machine-wide rules.
/// </summary>
public static class ProtectionWriteConsent
{
    private static volatile bool _granted;

    public static bool Granted => _granted;

    public static void Set(bool granted) => _granted = granted;

    /// <summary>True when this process is a non-interactive (service) host.</summary>
    public static bool IsServiceHost => !Environment.UserInteractive;
}
