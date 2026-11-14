// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.RegularExpressions;

namespace Axiom.Presentation;

/// <summary>
/// One DKG home for the node, the guard, the CLI and Axiom. The vendor installer writes the
/// effective home into the Hermes config; Axiom's own module path is only a fallback. Reading the
/// same value everywhere prevents the guard from getting a 401 and losing the local graph.
/// </summary>
public static class DkgHomeResolver
{
    /// <summary>Axiom's managed module home, used when no Hermes config names one.</summary>
    public static string AxiomManagedHome(string localAppData) =>
        Path.Combine(localAppData, "Axiom", "modules", "dkg");

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
