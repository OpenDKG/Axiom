// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;

namespace Axiom.Core.Firewall;

/// <summary>
/// Platform-neutral firewall write gate shared by every <see cref="IFirewallPolicyAdapter"/>.
/// Writes are allowed when the explicit test override is present, or when the service host holds
/// persisted user consent for the shield. An interactive process never writes.
/// </summary>
public static class FirewallWriteGate
{
    public const string WriteEnableVariable = "AXIOM_ENABLE_FIREWALL_WRITES";

    public const string WriteConfirmVariable = "AXIOM_FIREWALL_WRITE_CONFIRM";

    public static bool IsOpen =>
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
}
