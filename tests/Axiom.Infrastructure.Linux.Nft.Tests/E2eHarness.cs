// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// Root-only end-to-end proof, driven by <c>scripts/linux/nft/e2e.sh</c>:
/// <c>&lt;test exe&gt; e2e &lt;state-dir&gt; &lt;pid-of-a-curl-shell&gt;</c>. Applies a block rule for
/// <c>/usr/bin/curl</c> through the real engine (nft + cgroup fs), herds the given already-running
/// shell's curl children, reads back the table and counters, streams <c>nft monitor trace</c> for the
/// duration, then removes the rule and tears everything down. Exit code 0 only when every step
/// succeeded; the script does the curl runs and asserts on them.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public static class E2eHarness
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length < 2 || args[0] != "e2e")
        {
            Console.Error.WriteLine("usage: e2e <state-dir> [<command>] — see scripts/linux/nft/e2e.sh");
            return 2;
        }

        if (!OperatingSystem.IsLinux() || !Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine("e2e needs root on Linux");
            return 3;
        }

        var stateDir = args[1];
        var command = args.Length > 2 ? args[2] : "apply";
        var sink = new ConsoleSink();
        var cgroups = new AppCgroupManager(new ProcCgroupFs());
        using var adapter = new NftFirewallPolicyAdapter(
            new NftEnginePaths(stateDir),
            new NftTable(new NftProcessRunner()),
            cgroups,
            sink,
            () => true,
            TimeProvider.System);
        var ruleId = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
        var badId = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7");
        var spec = new RuleSpec
        {
            ManagedRuleId = ruleId,
            AppPath = "/usr/bin/curl",
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            CreatedBy = "e2e",
        };

        switch (command)
        {
            case "apply":
            {
                var result = await adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None).ConfigureAwait(false);
                Print("rule.apply", $"success={result.Success} state={result.State} error={result.ErrorCode} {result.ErrorMessage}");
                var rejected = await adapter.UpsertOwnedRuleAsync(spec with { ManagedRuleId = badId, RemoteAddresses = ["1.2.3"] }, CancellationToken.None).ConfigureAwait(false);
                Print("rule.apply(bad)", $"success={rejected.Success} state={rejected.State} error={rejected.ErrorCode} {rejected.ErrorMessage}");
                var enforcement = adapter.Enforcement!;
                Print("enforcement", $"generation={enforcement.Generation} applied={enforcement.AppliedRuleCount} rejected={enforcement.RejectedRules.Count} fileError={enforcement.FileError}");
                foreach (var app in cgroups.Apps)
                {
                    Print("cgroup", $"{app.Key} -> /sys/fs/cgroup/{app.Value}");
                }

                return result.Success && enforcement.AppliedRuleCount == 1 && enforcement.RejectedRules.Count == 1 ? 0 : 1;
            }

            case "attribute":
            {
                // Called while the script's curl is sleeping: herd it into the app cgroup.
                await adapter.PublishAsync(CancellationToken.None).ConfigureAwait(false);
                var report = adapter.Attribute();
                foreach (var placement in report.Placements)
                {
                    Print("placement", AppCgroupManager.Describe(placement));
                }

                var curlPids = report.Placements.Where(p => p.Moved && p.ExePath == "/usr/bin/curl").Select(p => p.Pid).ToList();
                Print("attribution", $"moved={report.Placements.Count(p => p.Moved)} failed={report.Placements.Count(p => !p.Moved)} curlPids={string.Join(',', curlPids)}");
                return report.Placements.All(p => p.Moved) ? 0 : 1;
            }

            case "trace":
            {
                // Streams blocked attempts as flow events for the given number of seconds.
                var seconds = args.Length > 3 ? int.Parse(args[3], CultureInfo.InvariantCulture) : 6;
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
                var monitor = new NftTraceMonitor(
                    new NftTraceProcessSource(),
                    new ProcNetSocketLookup(),
                    id => cgroups.Apps
                        .Select(app => (Pids: new ProcCgroupFs().ReadProcs(app.Value), Path: (string?)app.Key))
                        .Select(app => (Pid: app.Pids.Count > 0 ? app.Pids[0] : -1, app.Path))
                        .Cast<(int Pid, string? Path)?>()
                        .FirstOrDefault(),
                    sink,
                    TimeProvider.System);
                try
                {
                    await monitor.RunAsync(cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Timed window elapsed.
                }

                Print("trace", $"events={monitor.EventsEmitted}");
                return 0;
            }

            case "verify":
            {
                var report = await adapter.VerifyAsync(spec, CancellationToken.None).ConfigureAwait(false);
                Print("rule.verify", $"present={report.PresentInOs} matches={report.MatchesSpec} effective={report.EffectiveAction} rejection={report.FilterRejectionReason}");
                foreach (var note in report.Notes)
                {
                    Print("note", note);
                }

                var capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None).ConfigureAwait(false);
                Print("capabilities", $"status={capabilities.Status} running={capabilities.FirewallServiceRunning} reason={capabilities.Reason}");
                return report.PresentInOs && report.EffectiveAction == FirewallAction.Block ? 0 : 1;
            }

            case "remove":
            {
                var removed = await adapter.RemoveOwnedRuleAsync(ruleId, CancellationToken.None).ConfigureAwait(false);
                var removedBad = await adapter.RemoveOwnedRuleAsync(badId, CancellationToken.None).ConfigureAwait(false);
                Print("rule.remove", $"success={removed.Success} {removed.ErrorMessage} bad={removedBad.Success}");
                return removed.Success && removedBad.Success ? 0 : 1;
            }

            case "teardown":
            {
                await adapter.TeardownAsync(CancellationToken.None).ConfigureAwait(false);
                var gone = !await new NftTable(new NftProcessRunner()).ExistsAsync(CancellationToken.None).ConfigureAwait(false);
                Print("teardown", $"tableGone={gone} sliceGone={!Directory.Exists("/sys/fs/cgroup/axiom.slice")}");
                return gone ? 0 : 1;
            }

            default:
                Console.Error.WriteLine($"unknown command {command}");
                return 2;
        }
    }

    private static void Print(string step, string text) =>
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"[{Stopwatch.GetTimestamp() % 1000000:D6}] {step}: {text}"));

    private sealed class ConsoleSink : IFilterEventSink
    {
        public void Emit(string ndjsonLine) => Console.WriteLine("event " + ndjsonLine);
    }
}
