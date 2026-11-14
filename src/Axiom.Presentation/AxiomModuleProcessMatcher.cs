// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Pure command-line matcher used by desktop window hiders to identify background
/// console and script processes belonging to Axiom's optional modules (DKG node,
/// Agent Blackbox dashboard, sync tasks, and installer wrappers).
/// </summary>
public static class AxiomModuleProcessMatcher
{
    public static bool IsAxiomModuleCommandLine(string? commandLine) =>
        !string.IsNullOrWhiteSpace(commandLine) &&
        (IsDkgCommandLine(commandLine) || IsBlackboxCommandLine(commandLine));

    public static bool IsDkgCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        if (commandLine.Contains(@"\Axiom\modules\dkg\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/Axiom/modules/dkg/", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("start-blackbox-dkg.ps1", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var isHermesBlackboxPath =
            commandLine.Contains(@"\hermes\blackbox\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains(@"\.hermes\blackbox\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/hermes/blackbox/", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/.hermes/blackbox/", StringComparison.OrdinalIgnoreCase);

        return isHermesBlackboxPath &&
               (commandLine.Contains(@"\dkg", StringComparison.OrdinalIgnoreCase) ||
                commandLine.Contains("/dkg", StringComparison.OrdinalIgnoreCase) ||
                commandLine.Contains("dkg-engine", StringComparison.OrdinalIgnoreCase) ||
                commandLine.Contains("index.mjs", StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsBlackboxCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        if (commandLine.Contains(@"\Axiom\modules\blackbox\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/Axiom/modules/blackbox/", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("start-blackbox-dashboard.ps1", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("start-dashboard.py", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var isHermesBlackboxPath =
            commandLine.Contains(@"\hermes\blackbox\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains(@"\.hermes\blackbox\", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/hermes/blackbox/", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/.hermes/blackbox/", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains(@"\hermes\plugins\blackbox", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains(@"\.hermes\plugins\blackbox", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/hermes/plugins/blackbox", StringComparison.OrdinalIgnoreCase) ||
            commandLine.Contains("/.hermes/plugins/blackbox", StringComparison.OrdinalIgnoreCase);

        if (isHermesBlackboxPath &&
            (commandLine.Contains("dashboard", StringComparison.OrdinalIgnoreCase) ||
             commandLine.Contains("blackbox", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return commandLine.Contains("hermes", StringComparison.OrdinalIgnoreCase) &&
               commandLine.Contains("blackbox dashboard", StringComparison.OrdinalIgnoreCase);
    }
}
