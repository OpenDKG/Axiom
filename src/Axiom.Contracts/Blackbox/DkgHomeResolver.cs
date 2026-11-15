// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.RegularExpressions;

namespace Axiom.Contracts.Blackbox;

/// <summary>
/// One DKG home for the node, the guard, the CLI and Axiom. The vendor installer writes the
/// effective home into the Hermes config; Axiom's own module path is only a fallback. Reading the
/// same value everywhere prevents the guard from getting a 401 and losing the local graph.
/// </summary>
public static class DkgHomeResolver
{
    /// <summary>Axiom's managed CLI home, used by Axiom's own standalone DKG install.</summary>
    public static string AxiomManagedHome(string localAppData) =>
        Path.Combine(localAppData, "Axiom", "modules", "dkg");

    /// <summary>
    /// The DKG home the Blackbox vendor installer actually creates and writes into the Hermes
    /// config. This is the home the node, the guard and the CLI share in a Blackbox install.
    /// </summary>
    public static string BundledBlackboxHome(string localAppData) =>
        Path.Combine(localAppData, "Axiom", "modules", "blackbox", "agent-blackbox", ".dkg");

    /// <summary>The home Axiom's optional CLI installer passes as <c>DKG_HOME</c>.</summary>
    public static string StandaloneHome(string localAppData) =>
        Path.Combine(localAppData, "Axiom", "modules", "dkg-home");

    /// <summary>Every home an install can legitimately leave behind, most specific first.</summary>
    public static IReadOnlyList<string> CandidateHomes(string localAppData) =>
    [
        BundledBlackboxHome(localAppData),
        StandaloneHome(localAppData),
        AxiomManagedHome(localAppData),
    ];

    /// <summary>
    /// Reads the API bearer token the DKG node writes to <c>auth.token</c>. The file has a comment
    /// line above the token; a naive trim sends the comment too and the node answers 401/400.
    /// </summary>
    public static string? ReadToken(string? tokenFileContent)
    {
        if (string.IsNullOrWhiteSpace(tokenFileContent))
        {
            return null;
        }

        foreach (var line in tokenFileContent.Split('\n'))
        {
            var value = line.Trim().Trim('\r');
            if (value.Length == 0 || value.StartsWith('#'))
            {
                continue;
            }

            return value;
        }

        return null;
    }

    /// <summary>Reads the node's loopback API port from <c>api.port</c>.</summary>
    public static int? ReadApiPort(string? portText) =>
        int.TryParse(portText?.Trim(), out var port) && port is > 0 and <= 65535 ? port : null;

    /// <summary>
    /// The home that exists on disk: a configured home wins when it is present, otherwise the
    /// bundled Blackbox home, the optional standalone home, or Axiom's managed path.
    /// </summary>
    public static string ResolveEffective(
        string localAppData,
        Func<string, string?> readConfig,
        Func<string, bool> directoryExists)
    {
        var configured = ReadConfiguredHome(ReadConfigSafe(localAppData, readConfig) ?? string.Empty);
        if (!string.IsNullOrWhiteSpace(configured) && directoryExists(configured))
        {
            return configured;
        }

        foreach (var home in CandidateHomes(localAppData))
        {
            if (directoryExists(home))
            {
                return home;
            }
        }

        return string.IsNullOrWhiteSpace(configured)
            ? BundledBlackboxHome(localAppData)
            : configured;
    }

    private static string? ReadConfigSafe(string localAppData, Func<string, string?> readConfig)
    {
        try
        {
            return readConfig(Path.Combine(localAppData, "hermes", "config.yaml"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Extracts <c>dkg_home</c> from a Hermes config, if present.</summary>
    public static string? ReadConfiguredHome(string configYaml)
    {
        if (string.IsNullOrWhiteSpace(configYaml))
        {
            return null;
        }

        var match = Regex.Match(configYaml, @"(?m)^\s*dkg_home:\s*(?<value>.+?)\s*$");
        if (!match.Success)
        {
            return null;
        }

        var value = match.Groups["value"].Value.Trim().Trim('"', '\'');
        return value.Length == 0 ? null : value;
    }

    /// <summary>
    /// Extracts <c>dkg_bin</c> from a Hermes config, if present.
    /// </summary>
    public static string? ReadConfiguredBin(string configYaml)
    {
        if (string.IsNullOrWhiteSpace(configYaml))
        {
            return null;
        }

        var match = Regex.Match(configYaml, @"(?m)^\s*dkg_bin:\s*(?<value>.+?)\s*$");
        if (!match.Success)
        {
            return null;
        }

        var value = match.Groups["value"].Value.Trim().Trim('"', '\'');
        return value.Length == 0 ? null : value;
    }

    /// <summary>
    /// The effective home: the configured value when the Hermes config exists, otherwise Axiom's
    /// managed path. The directory itself is not required to exist yet.
    /// </summary>
    public static string Resolve(string localAppData, Func<string, string?> readConfig)
    {
        var configPath = Path.Combine(localAppData, "hermes", "config.yaml");
        var configured = readConfig(configPath);
        var home = ReadConfiguredHome(configured ?? string.Empty);
        return string.IsNullOrWhiteSpace(home) ? AxiomManagedHome(localAppData) : home;
    }
}
