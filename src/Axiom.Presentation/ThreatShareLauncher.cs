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

    internal const string ManualReportStarted = "Axiom manual reporter ready.";
    internal const string ManualConsentPathVariable = "AXIOM_MANUAL_REPORT_CONSENT_PATH";

    // The installed Blackbox supports a process-scoped BLACKBOX_REPORT override. Load the
    // underlying profile first, accept terms only for the confirmed operation, and invoke the
    // reporter directly so the override never starts a dashboard or enables other agent hooks.
    internal const string ManualReportBootstrap = """
        import argparse, os, sys
        from pathlib import Path
        from plugins.blackbox.kernel.config import load_blackbox_config
        from plugins.blackbox.community import consent, sharing
        from plugins.blackbox.community.report_cli import report_command as rc

        effective = load_blackbox_config()
        os.environ.pop("BLACKBOX_REPORT", None)
        saved = load_blackbox_config()
        if effective.report or saved.report:
            sys.exit("Not submitted: turn off Blackbox automatic sharing first.")
        if not saved.context_graph_id or saved.community_sandbox:
            sys.exit("Not submitted: a non-sandbox Blackbox graph must be configured.")
        p = argparse.ArgumentParser(prog="blackbox")
        rc.add_report_parser(p.add_subparsers(dest="cmd"))
        args = p.parse_args(sys.argv[1:])
        terms = consent.terms_text()
        if not terms:
            sys.exit("Not submitted: Blackbox reporter terms could not be read.")
        receipt_path = os.environ.pop("AXIOM_MANUAL_REPORT_CONSENT_PATH", "")
        if not receipt_path or not callable(getattr(consent, "_record_path", None)):
            sys.exit("Not submitted: this Blackbox build cannot isolate manual reporter consent.")
        if not callable(getattr(sharing, "_after_send", None)) or not callable(getattr(sharing, "_ledger_share", None)):
            sys.exit("Not submitted: this Blackbox build cannot isolate manual reporter retries.")

        # Use the vendor's ledger without enrolling this report for retry or renewal.
        def record_one_attempt(cfg, finding, name, subject, quads, outcome, detail):
            if outcome is not sharing.ShareOutcome.NOT_ALLOWED:
                sharing._ledger_share(
                    finding, subject, name, ok=outcome is sharing.ShareOutcome.ACCEPTED,
                    error=detail, outcome=outcome.value)

        sharing._after_send = record_one_attempt
        consent._record_path = lambda: Path(receipt_path)
        receipt = consent.current()
        if receipt is None or not consent.in_force() or receipt.terms_hash != consent.terms_hash(terms):
            if consent.record() is None:
                sys.exit("Not submitted: Blackbox reporter consent could not be saved.")
        os.environ["BLACKBOX_REPORT"] = "true"
        print("Axiom manual reporter ready.", flush=True)
        sys.exit(rc.cmd_report(args))
        """;

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
        "--severity", ThreatShareVocabulary.NormalizeSeverity(candidate.Severity),
    ];

    internal static IReadOnlyList<ThreatShareLaunchPlan> BuildManualReportPlans(
        IReadOnlyList<string> arguments,
        string blackboxRoot,
        string? runtimePython,
        string? venvPython,
        string hermesHome)
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [BlackboxPaths.HermesHomeVariable] = hermesHome,
            ["PYTHONPATH"] = blackboxRoot,
            [ManualConsentPathVariable] = ThreatSharingConsent.DefaultPath + ".blackbox-terms.json",
        };

        return new[] { runtimePython, venvPython }
            .OfType<string>()
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(path => new ThreatShareLaunchPlan(
                path, ["-c", ManualReportBootstrap, .. arguments.Skip(1)], blackboxRoot, environment,
                "the isolated Blackbox manual reporter"))
            .ToList();
    }

    /// <summary>Retraction plans. The leading <c>blackbox</c> token is dropped for the direct module.</summary>
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
