// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.RegularExpressions;

namespace Axiom.Presentation;

/// <summary>
/// Trader Shield protects crypto wallets: the agent cannot open a wallet keystore, and seed phrases
/// or private keys it handles are flagged and blocked when it tries to send them out. The vendor
/// reads the mode from <c>plugins.entries.blackbox.shields.trader</c>.
/// </summary>
public static class TraderShieldProvisioner
{
    /// <summary>Wallet ids the pinned Blackbox build supports.</summary>
    public static IReadOnlyList<string> SupportedWallets { get; } =
    [
        "metamask",
        "phantom",
        "exodus",
        "electrum",
        "solana-cli",
        "rabby",
        "coinbase-wallet",
        "trust-wallet",
        "okx-wallet",
        "keplr",
        "solflare",
    ];

    /// <summary>Guard every supported wallet; keep addresses empty until the operator adds them.</summary>
    public static string BuildSection(bool enabled = true, IEnumerable<string>? addresses = null)
    {
        var wallets = string.Join(", ", SupportedWallets);
        var lines = new List<string>
        {
            "      shields:",
            "        trader:",
            "          enabled: " + (enabled ? "true" : "false"),
            "          wallets: [" + wallets + "]",
        };

        var valid = (addresses ?? [])
            .Select(address => address.Trim().ToLowerInvariant())
            .Where(IsWalletAddress)
            .Distinct()
            .ToArray();

        if (valid.Length == 0)
        {
            lines.Add("          addresses: []");
        }
        else
        {
            lines.Add("          addresses:");
            lines.AddRange(valid.Select(address => "            - " + address));
        }

        return string.Join("\n", lines);
    }

    /// <summary>
    /// Inserts or replaces the trader section in a Hermes config, preserving every other line.
    /// </summary>
    public static string Apply(string configYaml, bool enabled = true, IEnumerable<string>? addresses = null)
    {
        var section = BuildSection(enabled, addresses);
        if (string.IsNullOrWhiteSpace(configYaml))
        {
            return "plugins:\n  entries:\n    blackbox:\n" + section + "\n";
        }

        var normalized = configYaml.Replace("\r\n", "\n");
        if (Regex.IsMatch(normalized, @"(?m)^\s+shields:\s*$"))
        {
            // Replace the existing shields block up to the next key at the same or lower indent.
            normalized = Regex.Replace(
                normalized,
                @"(?ms)^\s+shields:\s*\n(?:[ \t]+.*\n|\s*\n)*",
                section + "\n");
            return normalized;
        }

        var anchor = Regex.Match(normalized, @"(?m)^(?<indent>\s*)blackbox:\s*$");
        if (!anchor.Success)
        {
            return normalized.TrimEnd() + "\n    blackbox:\n" + section + "\n";
        }

        var insertAt = anchor.Index + anchor.Length;
        return normalized[..insertAt] + "\n" + section + normalized[insertAt..];
    }

    /// <summary>True when the config enables the trader shield for at least one wallet.</summary>
    public static bool IsEnabled(string? configYaml) =>
        !string.IsNullOrWhiteSpace(configYaml) &&
        Regex.IsMatch(configYaml, @"(?ms)^\s+trader:\s*\n(?:[ \t]+.*\n)*?\s+enabled:\s*true\s*$");

    /// <summary>EVM address: 0x plus forty hex characters.</summary>
    public static bool IsWalletAddress(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        Regex.IsMatch(value.Trim(), @"^0x[0-9a-fA-F]{40}$");

    /// <summary>
    /// Applies the section to the Hermes config the guard reads. A missing config is left alone:
    /// the vendor installer owns that file.
    /// </summary>
    public static bool ApplyToFile(string configPath)
    {
        try
        {
            if (!System.IO.File.Exists(configPath))
            {
                return false;
            }

            var text = System.IO.File.ReadAllText(configPath);
            var updated = Apply(text);
            if (!string.Equals(text, updated, StringComparison.Ordinal))
            {
                System.IO.File.WriteAllText(configPath, updated);
            }

            return true;
        }
        catch (Exception exception) when (exception is System.IO.IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
