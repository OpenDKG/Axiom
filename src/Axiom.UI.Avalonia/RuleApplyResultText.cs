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

    /// <summary>
    /// Status line for a batch (rule import). Counts only successful results as applied and splits
    /// them the same way <see cref="Describe"/> words one rule: published but not acknowledged
    /// (Pending, not enforced yet), installed but not race-free (Linux nft-only), connect-time
    /// proven (Linux BPF). With no such results the text is upstream's plain "Applied N" line, so
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
        var notRaceFree = succeeded.Count(result =>
            result.State != RuleState.Pending && result.ConnectTimeBlockingProven == false);
        var proven = succeeded.Count(result =>
            result.State != RuleState.Pending && result.ConnectTimeBlockingProven == true);

        var parts = new List<string>();
        if (proven > 0)
        {
            parts.Add($"{proven} connect-time blocking proven");
        }

        if (notRaceFree > 0)
        {
            parts.Add($"{notRaceFree} installed in {PlatformText.FilterName} but not race-free");
        }

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
