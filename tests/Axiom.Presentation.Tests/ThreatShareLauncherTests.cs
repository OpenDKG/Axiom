// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatShareLauncherTests
{
    private static Axiom.Contracts.Threat.ThreatShareCandidate Candidate() =>
        new()
        {
            Id = "ioc:domain:c2.example.net",
            IndicatorType = "domain",
            Value = "c2.example.net",
            Reason = "command-and-control",
            Context = "fetched-by-tool",
            Source = Axiom.Contracts.Threat.ThreatShareSource.AiAnalyst,
            Detail = "do not send this",
        };

    [Fact]
    public void Plans_prefer_the_committed_runtime_then_the_launcher_then_the_module()
    {
        var plans = ThreatShareLauncher.BuildPlans(
            ["blackbox", "report", "--retract", Candidate().Id],
            blackboxRoot: @"C:\axiom\blackbox",
            runtimePython: @"C:\hermes\env\Scripts\python.exe",
            hermesExe: @"C:\axiom\blackbox\venv\Scripts\hermes.exe",
            venvPython: @"C:\axiom\blackbox\venv\Scripts\python.exe",
            hermesHome: @"C:\Users\lab\AppData\Local\hermes");

        Assert.Equal(3, plans.Count);
        Assert.Equal(@"C:\hermes\env\Scripts\python.exe", plans[0].FileName);
        Assert.Equal("-c", plans[0].Arguments[0]);
        Assert.Equal(ThreatShareLauncher.HermesBootstrap, plans[0].Arguments[1]);
        Assert.Equal("blackbox", plans[0].Arguments[2]);
        Assert.Contains("report", plans[0].Arguments);

        Assert.EndsWith("hermes.exe", plans[1].FileName, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("blackbox", plans[1].Arguments[0]);

        Assert.EndsWith("python.exe", plans[2].FileName, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("report", plans[2].Arguments[2]);
        Assert.DoesNotContain("blackbox", plans[2].Arguments);

        Assert.All(plans, plan =>
        {
            Assert.Equal(@"C:\axiom\blackbox", plan.WorkingDirectory);
            Assert.Equal(@"C:\axiom\blackbox", plan.Environment["PYTHONPATH"]);
            Assert.Equal(@"C:\Users\lab\AppData\Local\hermes", plan.Environment["HERMES_HOME"]);
        });
    }

    [Fact]
    public void Missing_optional_launchers_are_skipped()
    {
        var plans = ThreatShareLauncher.BuildPlans(
            ["blackbox", "report", "--retract", Candidate().Id], @"C:\axiom\blackbox", runtimePython: null, hermesExe: null,
            venvPython: @"C:\axiom\blackbox\venv\Scripts\python.exe", hermesHome: @"C:\h");

        var plan = Assert.Single(plans);
        Assert.EndsWith("python.exe", plan.FileName, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Manual_reporting_uses_only_the_guarded_child_and_an_isolated_consent_receipt()
    {
        var plans = ThreatShareLauncher.BuildManualReportPlans(
            ThreatShareLauncher.ReportArguments(Candidate()),
            @"C:\axiom\blackbox",
            @"C:\hermes\env\Scripts\python.exe",
            @"C:\axiom\blackbox\venv\Scripts\python.exe",
            @"C:\hermes");

        Assert.Equal(2, plans.Count);
        Assert.All(plans, plan =>
        {
            Assert.Equal(ThreatShareLauncher.ManualReportBootstrap, plan.Arguments[1]);
            Assert.Equal("report", plan.Arguments[2]);
            Assert.DoesNotContain("BLACKBOX_REPORT", plan.Environment.Keys);
            Assert.Equal(ThreatSharingConsent.DefaultPath + ".blackbox-terms.json",
                plan.Environment[ThreatShareLauncher.ManualConsentPathVariable]);
        });
    }

    [Fact]
    public void The_report_arguments_use_only_the_validated_candidate_fields()
    {
        var arguments = ThreatShareLauncher.ReportArguments(Candidate());

        Assert.Contains("--ioc-type", arguments);
        Assert.Contains("domain", arguments);
        Assert.Contains("--value", arguments);
        Assert.Contains("c2.example.net", arguments);
        Assert.Contains("--context", arguments);
        Assert.Contains("fetched-by-tool", arguments);
        Assert.DoesNotContain("do not send this", arguments);
    }

    [Fact]
    public void The_runtime_interpreter_is_read_from_facts_json()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-threatshare-" + Guid.NewGuid().ToString("N"));
        try
        {
            var env = Path.Combine(root, "hermes", "installs", "abc", "environments", "env1", "venv");
            Directory.CreateDirectory(Path.Combine(env, "Scripts"));
            File.WriteAllText(Path.Combine(env, "Scripts", "python.exe"), string.Empty);
            Directory.CreateDirectory(Path.Combine(root, "hermes", "installs", "abc"));
            File.WriteAllText(
                Path.Combine(root, "hermes", "installs", "abc", "facts.json"),
                JsonSerializer.Serialize(new
                {
                    packages = new { venv = new { environment = env } },
                }));

            var python = ThreatShareLauncher.FindRuntimePython(root);

            Assert.Equal(Path.Combine(env, "Scripts", "python.exe"), python);
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
                // A locked temp file must not fail the test.
            }
        }
    }

    [Fact]
    public void A_missing_install_directory_yields_no_interpreter()
    {
        Assert.Null(ThreatShareLauncher.FindRuntimePython(
            Path.Combine(Path.GetTempPath(), "axiom-missing-" + Guid.NewGuid().ToString("N"))));
    }
}
