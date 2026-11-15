// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.RegularExpressions;

namespace Axiom.Presentation;

/// <summary>Parsed local Trader Shield configuration.</summary>
public sealed record TraderShieldSettings(
    bool Enabled,
    IReadOnlyList<string> Wallets,
    IReadOnlyList<string> Addresses);

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

    /// <summary>Resolves the authoritative Hermes config path read by the Blackbox guard.</summary>
    public static string ResolveConfigPath(string? localAppData = null, string? userProfile = null)
    {
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var profile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return HermesConfigLocation.Resolve(local, profile, System.IO.File.Exists);
    }

    /// <summary>Guard the chosen wallets (or all supported wallets when null) and keep validated addresses.</summary>
    public static string BuildSection(
        bool enabled = true,
        IEnumerable<string>? addresses = null,
        IEnumerable<string>? wallets = null)
    {
        var selectedWallets = NormalizeWallets(wallets);
        var lines = new List<string>
        {
            "      shields:",
            "        trader:",
            "          enabled: " + (enabled ? "true" : "false"),
            "          wallets: [" + string.Join(", ", selectedWallets) + "]",
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
    public static string Apply(
        string configYaml,
        bool enabled = true,
        IEnumerable<string>? addresses = null,
        IEnumerable<string>? wallets = null)
    {
        var section = BuildSection(enabled, addresses, wallets);
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

    /// <summary>Reads Trader Shield settings from a Hermes YAML text.</summary>
    public static TraderShieldSettings Read(string? configYaml)
    {
        if (string.IsNullOrWhiteSpace(configYaml))
        {
            return new TraderShieldSettings(false, SupportedWallets, []);
        }

        var lines = configYaml.Replace("\r\n", "\n").Split('\n');
        var traderIndex = Array.FindIndex(lines, line => Regex.IsMatch(line, @"^[ \t]+trader:[ \t]*$"));
        if (traderIndex < 0)
        {
            return new TraderShieldSettings(false, SupportedWallets, []);
        }

        var traderIndent = LeadingSpaces(lines[traderIndex]);
        var enabled = false;
        var hasWalletsKey = false;
        var wallets = new List<string>();
        var addresses = new List<string>();
        string? activeList = null;

        for (var i = traderIndex + 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var indent = LeadingSpaces(line);
            if (indent <= traderIndent)
            {
                break;
            }

            var trimmed = line.Trim();
            if (trimmed.StartsWith('#'))
            {
                continue;
            }

            if (trimmed.StartsWith("- ", StringComparison.Ordinal))
            {
                var item = trimmed[2..].Trim().Trim('\'', '"');
                if (activeList == "wallets" && !string.IsNullOrEmpty(item))
                {
                    wallets.Add(item);
                }
                else if (activeList == "addresses" && IsWalletAddress(item))
                {
                    addresses.Add(item.ToLowerInvariant());
                }

                continue;
            }

            activeList = null;
            var enabledMatch = Regex.Match(trimmed, @"^enabled:\s*(true|false)\b", RegexOptions.IgnoreCase);
            if (enabledMatch.Success)
            {
                enabled = string.Equals(enabledMatch.Groups[1].Value, "true", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (trimmed.StartsWith("wallets:", StringComparison.Ordinal))
            {
                hasWalletsKey = true;
                var inline = ParseInlineList(trimmed["wallets:".Length..]);
                if (inline is not null)
                {
                    wallets.AddRange(inline);
                }
                else
                {
                    activeList = "wallets";
                }

                continue;
            }

            if (trimmed.StartsWith("addresses:", StringComparison.Ordinal))
            {
                var inline = ParseInlineList(trimmed["addresses:".Length..]);
                if (inline is not null)
                {
                    addresses.AddRange(inline.Where(IsWalletAddress).Select(address => address.ToLowerInvariant()));
                }
                else
                {
                    activeList = "addresses";
                }
            }
        }

        var resolvedWallets = hasWalletsKey ? NormalizeWallets(wallets) : SupportedWallets;
        var resolvedAddresses = addresses.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return new TraderShieldSettings(enabled, resolvedWallets, resolvedAddresses);
    }

    /// <summary>Reads Trader Shield settings from disk, falling back to safe defaults when absent.</summary>
    public static TraderShieldSettings ReadFromFile(string configPath)
    {
        try
        {
            return System.IO.File.Exists(configPath)
                ? Read(System.IO.File.ReadAllText(configPath))
                : new TraderShieldSettings(false, SupportedWallets, []);
        }
        catch (Exception exception) when (exception is System.IO.IOException or UnauthorizedAccessException)
        {
            return new TraderShieldSettings(false, SupportedWallets, []);
        }
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
    public static bool ApplyToFile(
        string configPath,
        bool enabled = true,
        IEnumerable<string>? addresses = null,
        IEnumerable<string>? wallets = null)
    {
        try
        {
            if (!System.IO.File.Exists(configPath) || StorageSafety.IsReparsePointInPath(configPath))
            {
                return false;
            }

            var text = System.IO.File.ReadAllText(configPath);
            var updated = Apply(text, enabled, addresses, wallets);
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

    private static IReadOnlyList<string> NormalizeWallets(IEnumerable<string>? wallets)
    {
        if (wallets is null)
        {
            return SupportedWallets;
        }

        var chosen = new HashSet<string>(
            wallets.Where(wallet => !string.IsNullOrWhiteSpace(wallet))
                .Select(wallet => wallet.Trim().ToLowerInvariant()),
            StringComparer.OrdinalIgnoreCase);

        return SupportedWallets
            .Where(chosen.Contains)
            .ToArray();
    }

    private static int LeadingSpaces(string line)
    {
        var count = 0;
        while (count < line.Length && (line[count] == ' ' || line[count] == '\t'))
        {
            count++;
        }

        return count;
    }

    private static string[]? ParseInlineList(string remainder)
    {
        var trimmed = remainder.Trim();
        if (!trimmed.StartsWith('[') || !trimmed.EndsWith(']'))
        {
            return null;
        }

        var inner = trimmed[1..^1].Trim();
        if (inner.Length == 0)
        {
            return [];
        }

        return inner
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(item => item.Trim('\'', '"'))
            .Where(item => item.Length > 0)
            .ToArray();
    }
}
