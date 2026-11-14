// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Contracts.Firewall;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Status line for a <see cref="RuleApplyResult"/>. A successful result is "applied and verified"
/// only when the adapter verified enforcement; a <see cref="RuleState.Pending"/> result (macOS:
/// published, filter acknowledgement outstanding) says so and never claims enforcement. Windows
/// adapters never return Pending, so their text is unchanged.
/// </summary>
public static class RuleApplyResultText
{
    public static string Describe(RuleApplyResult result, string subject)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        if (!result.Success)
        {
            return $"{subject} failed: {result.ErrorCode} — {result.ErrorMessage}";
        }

        if (result.State == RuleState.Pending)
        {
            return $"{subject} published; waiting for {PlatformText.FilterName} to acknowledge it (not enforced yet" +
                   $"{(string.IsNullOrWhiteSpace(result.ErrorMessage) ? string.Empty : ": " + result.ErrorMessage)}).";
        }

        var at = result.VerifiedUtc?.ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "unknown";
        return result.ConnectTimeBlockingProven switch
        {
            // Linux only: the nft rule is in the live table, but a fresh process can still connect during
            // the attribution window. Never word that as plain "applied and verified".
            false => $"{subject} installed in {PlatformText.FilterName} and read back at {at}; not race-free: {result.CoverageReason ?? "a newly launched process can connect during the ~1 s cgroup attribution window"}.",
            true => $"{subject} applied; verified at {at}; connect-time blocking proven (a new process is refused at connect()).",
            null => $"{subject} applied; verified at {at}.",
        };
    }
}
