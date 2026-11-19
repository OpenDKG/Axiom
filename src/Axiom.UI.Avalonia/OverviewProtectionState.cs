// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.UI.Avalonia;

/// <summary>
/// What the Overview status line may claim. <paramref name="Enforcement"/> is the OS filter's
/// report on macOS/Linux and null on Windows, where Windows Firewall applies the written rules.
/// </summary>
public sealed record OverviewProtectionState(
    bool FirewallWritesEnabled,
    bool FirewallProtectionActive,
    bool PrivacyShieldActive,
    FilterEnforcementSummary? Enforcement);
