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

        return $"{subject} applied; verified at {result.VerifiedUtc?.ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "unknown"}.";
    }
}
