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
            return $"{subject} published; waiting for the network filter to acknowledge it (not enforced yet" +
                   $"{(string.IsNullOrWhiteSpace(result.ErrorMessage) ? string.Empty : ": " + result.ErrorMessage)}).";
        }

        return $"{subject} applied; verified at {result.VerifiedUtc?.ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "unknown"}.";
    }

    /// <summary>
    /// Status line for a batch (rule import). Counts only successful results as applied and splits
    /// them the same way <see cref="Describe"/> words one rule: published but not acknowledged
    /// (Pending, not enforced yet). (The Linux branch also names nft-only and BPF-proven results;
    /// that contract field does not exist on macOS.) With no such results the text is upstream's plain "Applied N" line, so
    /// Windows output is unchanged.
    /// </summary>
    public static string DescribeBatch(
        IReadOnlyList<RuleApplyResult> results,
        IReadOnlyList<string> failures,
        string subject)
    {
        ArgumentNullException.ThrowIfNull(results);
        ArgumentNullException.ThrowIfNull(failures);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        var succeeded = results.Where(result => result.Success).ToList();
        var pending = succeeded.Count(result => result.State == RuleState.Pending);
        var parts = new List<string>();
        if (pending > 0)
        {
            parts.Add($"{pending} published, waiting for the {PlatformText.Firewall} to acknowledge (not enforced yet)");
        }

        var applied = $"Applied {succeeded.Count} {subject}(s)" +
                      (parts.Count == 0 ? "." : ": " + string.Join("; ", parts) + ".");
        return failures.Count == 0
            ? applied
            : $"{applied.TrimEnd('.')}; {failures.Count} failed: {string.Join("; ", failures.Take(3))}";
    }
}
