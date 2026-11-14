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
        var lines = normalized.Split('\n').ToList();
        var shieldsIndex = lines.FindIndex(line => Regex.IsMatch(line, @"^([ \t]+)shields:[ \t]*$"));
        if (shieldsIndex >= 0)
        {
            // Replace only the shields block: it ends at the first non-blank line whose indentation
            // is not deeper than the shields key. A regex over indented lines used to swallow every
            // key after the block (mode, protected paths, enabled), which silently disabled
            // protection on the next start.
            var indent = Regex.Match(lines[shieldsIndex], @"^([ \t]+)").Groups[1].Value;
            var end = shieldsIndex + 1;
            while (end < lines.Count)
            {
                var line = lines[end];
                if (string.IsNullOrWhiteSpace(line))
                {
                    break;
                }

                var lineIndent = Regex.Match(line, @"^([ \t]*)").Groups[1].Value;
                if (lineIndent.Length <= indent.Length)
                {
                    break;
                }

                end++;
            }

            const int sectionIndent = 6;
            var replacement = section
                .Split('\n')
                .Select(line => line.Length <= sectionIndent ? line : indent + line[sectionIndent..])
                .ToArray();
            lines.RemoveRange(shieldsIndex, end - shieldsIndex);
            lines.InsertRange(shieldsIndex, replacement);
            return string.Join("\n", lines);
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
