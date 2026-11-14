// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

/// <summary>One way to run the vendor reporter: executable, arguments and the environment it needs.</summary>
public sealed record ThreatShareLaunchPlan(
    string FileName,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    IReadOnlyDictionary<string, string> Environment,
    string Description);

/// <summary>
/// Finds the interpreter that can actually run the Blackbox CLI and builds the command lines.
///
/// The vendor installer creates the Blackbox tree with its own Python venv but Hermes' package
/// manager commits a <em>different</em> dependency environment and, at boot,
/// <c>pm.environments.activate_dependencies</c> replaces every <c>site-packages</c> entry on
/// <c>sys.path</c> with that environment's. When the two use different Python minor versions the
/// venv's launcher imports compiled packages built for the other ABI and fails with
/// <c>No module named '_cffi_backend'</c> or <c>pydantic_core</c>. The committed environment's own
/// interpreter is the one whose ABI matches, so it is preferred; the vendor launcher and the
/// reporter's own module are kept as fallbacks.
/// </summary>
public static class ThreatShareLauncher
{
    /// <summary>Runs the vendor CLI with a working argv[0]; arguments follow the code.</summary>
    public const string HermesBootstrap =
        "import sys; sys.argv[0]='hermes'; from hermes_cli.main import main; sys.exit(main())";

    /// <summary>Runs the reporter subcommand directly, without plugin discovery.</summary>
    public const string ReportBootstrap =
        "import argparse,sys\n" +
        "from plugins.blackbox.community.report_cli import report_command as rc\n" +
        "p=argparse.ArgumentParser(prog='blackbox')\n" +
        "s=p.add_subparsers(dest='cmd')\n" +
        "rc.add_report_parser(s)\n" +
        "a=p.parse_args(sys.argv[1:])\n" +
        "sys.exit(rc.cmd_report(a))";

    /// <summary>
    /// Report arguments shared by every plan. Only the closed vocabulary Axiom validated locally is
    /// sent; severity is the reporter's own floor and carries no free text.
    /// </summary>
    public static IReadOnlyList<string> ReportArguments(ThreatShareCandidate candidate) =>
    [
        "blackbox", "report",
        "--type", "ioc",
        "--ioc-type", candidate.IndicatorType,
        "--value", candidate.Value,
        "--context", candidate.Context,
        "--severity", "high",
    ];

    /// <summary>Plans in preference order: committed interpreter, vendor launcher, reporter module.</summary>
    public static IReadOnlyList<ThreatShareLaunchPlan> BuildPlans(
        ThreatShareCandidate candidate,
        string blackboxRoot,
        string? runtimePython,
        string? hermesExe,
        string? venvPython,
        string hermesHome)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        return BuildPlans(
            ReportArguments(candidate), blackboxRoot, runtimePython, hermesExe, venvPython, hermesHome);
    }

    /// <summary>Plans for any reporter command; the leading <c>blackbox</c> token is dropped for the module.</summary>
    public static IReadOnlyList<ThreatShareLaunchPlan> BuildPlans(
        IReadOnlyList<string> commandArguments,
        string blackboxRoot,
        string? runtimePython,
        string? hermesExe,
        string? venvPython,
        string hermesHome)
    {
        ArgumentNullException.ThrowIfNull(commandArguments);
        var arguments = commandArguments;
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [BlackboxPaths.HermesHomeVariable] = hermesHome,
            ["PYTHONPATH"] = blackboxRoot,
        };

        var plans = new List<ThreatShareLaunchPlan>();

        if (!string.IsNullOrWhiteSpace(runtimePython))
        {
            plans.Add(new(
                runtimePython,
                ["-c", HermesBootstrap, .. arguments],
                blackboxRoot,
                environment,
                "the committed Hermes runtime"));
        }

        if (!string.IsNullOrWhiteSpace(hermesExe))
        {
            plans.Add(new(
                hermesExe,
                arguments,
                blackboxRoot,
                environment,
                "the vendor Hermes launcher"));
        }

        if (!string.IsNullOrWhiteSpace(venvPython))
        {
            var moduleArguments = arguments.Count > 0 &&
                                  string.Equals(arguments[0], "blackbox", StringComparison.Ordinal)
                ? arguments.Skip(1).ToArray()
                : arguments;
            plans.Add(new(
                venvPython,
                ["-c", ReportBootstrap, .. moduleArguments],
                blackboxRoot,
                environment,
                "the Blackbox reporter module"));
        }

        return plans;
    }

    /// <summary>
    /// The interpreter of the dependency environment Hermes commits in <c>facts.json</c>, newest
    /// install first. Missing or unreadable facts fall back to the newest environment directory.
    /// </summary>
    public static string? FindRuntimePython(string? localAppData = null, Func<string, bool>? fileExists = null)
    {
        var exists = fileExists ?? File.Exists;
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var installs = Path.Combine(local, "hermes", "installs");
        if (!Directory.Exists(installs))
        {
            return null;
        }

        IEnumerable<string> installDirectories;
        try
        {
            installDirectories = Directory.GetDirectories(installs)
                .OrderByDescending(path => SafeLastWrite(path))
                .ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        foreach (var install in installDirectories)
        {
            var fromFacts = ReadFactsPython(install, exists);
            if (fromFacts is not null)
            {
                return fromFacts;
            }

            var fromEnvironments = NewestEnvironmentPython(install, exists);
            if (fromEnvironments is not null)
            {
                return fromEnvironments;
            }
        }

        return null;
    }

    private static string? ReadFactsPython(string install, Func<string, bool> exists)
    {
        try
        {
            var facts = Path.Combine(install, "facts.json");
            if (!exists(facts))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(facts));
            if (!document.RootElement.TryGetProperty("packages", out var packages) ||
                !packages.TryGetProperty("venv", out var venv) ||
                !venv.TryGetProperty("environment", out var environment) ||
                environment.ValueKind is not JsonValueKind.String)
            {
                return null;
            }

            var root = environment.GetString();
            if (string.IsNullOrWhiteSpace(root))
            {
                return null;
            }

            var python = Path.Combine(root, "Scripts", "python.exe");
            return exists(python) ? python : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static string? NewestEnvironmentPython(string install, Func<string, bool> exists)
    {
        try
        {
            var root = Path.Combine(install, "environments");
            if (!Directory.Exists(root))
            {
                return null;
            }

            foreach (var environment in Directory.GetDirectories(root)
                         .OrderByDescending(SafeLastWrite))
            {
                var python = Path.Combine(environment, "venv", "Scripts", "python.exe");
                if (exists(python))
                {
                    return python;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return null;
    }

    private static DateTime SafeLastWrite(string path)
    {
        try
        {
            return Directory.GetLastWriteTimeUtc(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return DateTime.MinValue;
        }
    }
}
