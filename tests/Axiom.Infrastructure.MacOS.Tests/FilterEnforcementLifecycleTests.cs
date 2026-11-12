// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Monitoring;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// GitHub review 2026-11-12 (P0 #2/#3, High #4): publishing rules.json is not enforcement. Every
/// case of the handoff §5/§6 — absent, connected without rules, older generation, correct ack,
/// rule rejected, file rejected, disconnect after enforce, daemon restart, filter restart,
/// removal while disconnected, delayed ack, write ok but enforcement fails — must never report a
/// rule as Applied or give it an effective action without a verified acknowledgement.
/// </summary>
public sealed class FilterEnforcementLifecycleTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 12, 9, 0, 0, TimeSpan.Zero);

    private static FlowEvent RulesEvent(long generation, int applied = 0, string? error = null, params (string Id, string Reason)[] rejected)
    {
        var rejectedJson = string.Join(",", rejected.Select(entry => $"{{\"id\":\"{entry.Id}\",\"reason\":\"{entry.Reason}\"}}"));
        var errorJson = error is null ? "null" : $"\"{error}\"";
        return FlowEventParser.TryParse(string.Create(
            CultureInfo.InvariantCulture,
            $"{{\"type\":\"filter.rules\",\"generation\":{generation},\"applied\":{applied},\"rejected\":[{rejectedJson}],\"error\":{errorJson},\"dropped\":0}}"))!;
    }

    private static long PublishedGeneration(MacServicePaths paths) => FilterRulesFile.TryRead(paths.RulesFile)!.Generation;

    private static (MacServicePaths Paths, ManualTimeProvider Time, FilterStatus Status, MacFirewallPolicyAdapter Adapter) Harness(TempDirectory temp, TimeSpan? ackTimeout = null)
    {
        var paths = MacServicePaths.ForRoot(temp.Path);
        var time = new ManualTimeProvider(Start);
        var status = new FilterStatus();
        var adapter = new MacFirewallPolicyAdapter(paths, status, () => true, time, ackTimeout ?? TimeSpan.Zero);
        return (paths, time, status, adapter);
    }

    // --- FilterStatus: the four signals stay apart (High #4) ---

    [Fact]
    public void NeverSeenIsUnavailableAndConnectWithoutAckIsPending()
    {
        var status = new FilterStatus();
        Assert.Equal(FilterEnforcementState.Unavailable, status.Evaluate(1));
        Assert.Null(status.LastSeenUtc);

        status.ClientConnected();
        status.Hello("1.0", 1, Start);
        // A hello naming the generation is not an acknowledgement.
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(1));
        Assert.Null(status.AckedGeneration);
        Assert.Equal(Start, status.LastSeenUtc);
    }

    [Fact]
    public void ConnectAndAckVerifiesThenDisconnectWithdrawsImmediately()
    {
        var status = new FilterStatus();
        status.ClientConnected();
        status.Hello("1.0", 5, Start);
        status.RulesReported(RulesEvent(5, applied: 1), Start.AddMilliseconds(40));

        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(5));
        Assert.Equal(5, status.AckedGeneration);
        Assert.Equal(Start.AddMilliseconds(40), status.LastAckUtc);
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(6));

        status.ClientDisconnected();

        // No grace window: a hello 40 ms old proves nothing once the connection is gone.
        Assert.Equal(FilterEnforcementState.Degraded, status.Evaluate(5));
        Assert.False(status.IsConnected);
        Assert.Equal(5, status.AckedGeneration); // diagnostics are kept
        Assert.Equal(Start.AddMilliseconds(40), status.LastSeenUtc);
        var snapshot = status.Snapshot(5);
        Assert.False(snapshot.IsVerified);
        Assert.False(snapshot.Connected);
    }

    [Fact]
    public void ReconnectNeedsAFreshAckEvenForTheSameGeneration()
    {
        var status = new FilterStatus();
        status.ClientConnected();
        status.RulesReported(RulesEvent(5), Start);
        status.ClientDisconnected();
        status.ClientConnected();
        status.Hello("1.0", 5, Start.AddSeconds(1));

        // Same generation in the hello, no filter.rules on this connection: pending, not verified.
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(5));

        // A stale generation on the new connection stays pending.
        status.RulesReported(RulesEvent(4), Start.AddSeconds(2));
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(5));

        status.RulesReported(RulesEvent(5), Start.AddSeconds(3));
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(5));
    }

    [Fact]
    public void FileRejectionIsNotAnAckAndRecoveryNeedsAValidAck()
    {
        var status = new FilterStatus();
        status.ClientConnected();
        status.RulesReported(RulesEvent(5), Start);
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(5));

        // Generation 6 published, the filter rejects the file and keeps 5.
        status.RulesReported(RulesEvent(5, error: "invalid JSON"), Start.AddSeconds(1));
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(6));
        Assert.Equal(5, status.AckedGeneration);
        Assert.Equal("invalid JSON", status.Snapshot(6).FileRejectionSince(Start.AddMilliseconds(500)));
        Assert.Null(status.Snapshot(6).FileRejectionSince(Start.AddSeconds(2)));

        // Filter restart after invalid rules: recovery only once generation 7 is acknowledged.
        status.ClientDisconnected();
        status.ClientConnected();
        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(7));
        status.RulesReported(RulesEvent(7), Start.AddSeconds(3));
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(7));
    }

    [Fact]
    public async Task WaitReturnsOnAckDisconnectOrTimeoutAndAtOnceWhenNotConnected()
    {
        var status = new FilterStatus();
        var absent = Task.Run(() => status.WaitForAcknowledgementAsync(1, Start, TimeSpan.FromSeconds(30), CancellationToken.None));
        Assert.True(await Task.WhenAny(absent, Task.Delay(2000)) == absent, "not connected must not wait");

        status.ClientConnected();
        var timedOut = status.WaitForAcknowledgementAsync(1, Start, TimeSpan.FromMilliseconds(50), CancellationToken.None);
        Assert.True(await Task.WhenAny(timedOut, Task.Delay(2000)) == timedOut, "bounded wait must time out");

        var acked = status.WaitForAcknowledgementAsync(1, Start, TimeSpan.FromSeconds(30), CancellationToken.None);
        status.RulesReported(RulesEvent(1), Start.AddMilliseconds(5));
        Assert.True(await Task.WhenAny(acked, Task.Delay(2000)) == acked, "ack must release the wait");

        var dropped = status.WaitForAcknowledgementAsync(2, Start, TimeSpan.FromSeconds(30), CancellationToken.None);
        status.ClientDisconnected();
        Assert.True(await Task.WhenAny(dropped, Task.Delay(2000)) == dropped, "disconnect must release the wait");
    }

    // --- Adapter lifecycle (P0 #2/#3) ---

    [Fact]
    public async Task ExtensionAbsent_PublishesPendingNeverApplied()
    {
        using var temp = new TempDirectory();
        var (paths, _, _, adapter) = Harness(temp);
        using (adapter)
        {
            var curl = Specs.Block("/usr/bin/curl");
            var result = await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);

            Assert.True(result.Success);
            Assert.Equal(RuleState.Pending, result.State);
            Assert.Null(result.VerifiedUtc);
            Assert.Null(result.ErrorCode);
            Assert.Equal("awaiting AxiomFilter acknowledgement of generation 1 (the network extension has not connected)", result.ErrorMessage);
            Assert.Equal(1, PublishedGeneration(paths));

            var verify = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.True(verify.PresentInOs);
            Assert.True(verify.MatchesSpec);
            Assert.Null(verify.EffectiveAction);
            Assert.False(verify.EnforcementVerified);
            Assert.Contains(verify.Notes, note => note.Contains("never connected", StringComparison.Ordinal));

            var capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None);
            Assert.Equal(FirewallCapabilityStatus.Degraded, capabilities.Status);
            Assert.False(capabilities.FirewallServiceRunning);
            Assert.Contains("has not connected", capabilities.Reason, StringComparison.Ordinal);
            var enforcement = Assert.IsType<FilterEnforcementReport>(capabilities.FilterEnforcement);
            Assert.Equal(FilterEnforcementState.Unavailable, enforcement.State);
            Assert.False(enforcement.Connected);
            Assert.Equal(1, enforcement.PublishedGeneration);
            Assert.Null(enforcement.AckedGeneration);
            Assert.Null(enforcement.LastSeenUtc);

            Assert.Equal(RuleState.Pending, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);
        }
    }

    [Fact]
    public async Task ConnectedWithoutRulesLoaded_IsPending()
    {
        using var temp = new TempDirectory();
        var (_, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            status.ClientConnected();
            status.Hello("1.0", -1, time.GetUtcNow());

            var result = await adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/curl"), CancellationToken.None);
            Assert.Equal(RuleState.Pending, result.State);
            Assert.Equal("awaiting AxiomFilter acknowledgement of generation 1", result.ErrorMessage);

            var capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None);
            Assert.Equal(FirewallCapabilityStatus.Available, capabilities.Status);
            Assert.True(capabilities.FirewallServiceRunning);
            Assert.Contains("has not acknowledged rules generation 1", capabilities.Reason, StringComparison.Ordinal);
            Assert.Equal(FilterEnforcementState.Pending, capabilities.FilterEnforcement!.State);
        }
    }

    [Fact]
    public async Task OlderGenerationAcknowledged_IsPendingWithTheGapNamed()
    {
        using var temp = new TempDirectory();
        var (_, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            status.ClientConnected();
            var first = await adapter.UpsertOwnedRuleAsync(Specs.Block("/usr/bin/nc"), CancellationToken.None);
            Assert.Equal(RuleState.Pending, first.State);
            status.RulesReported(RulesEvent(1, applied: 1), time.GetUtcNow());

            var curl = Specs.Block("/usr/bin/curl");
            var second = await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            Assert.Equal(RuleState.Pending, second.State);
            Assert.Equal("awaiting AxiomFilter acknowledgement of generation 2 (last acknowledged generation 1)", second.ErrorMessage);

            var verify = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.Null(verify.EffectiveAction);
            Assert.False(verify.EnforcementVerified);
            Assert.Contains(verify.Notes, note => note.Contains("acknowledged generation 1, not 2", StringComparison.Ordinal));

            var enforcement = (await adapter.GetCapabilitiesAsync(CancellationToken.None)).FilterEnforcement!;
            Assert.Equal(1, enforcement.AckedGeneration);
            Assert.Equal(2, enforcement.PublishedGeneration);
            Assert.Equal(FilterEnforcementState.Pending, enforcement.State);
        }
    }

    [Fact]
    public async Task CorrectAckWithinTheWait_IsAppliedAtTheAckTime()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp, TimeSpan.FromSeconds(5));
        using (adapter)
        {
            status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            var ackTime = Start.AddMilliseconds(70);

            // The filter acks ~50 ms after the file lands (delayed acknowledgement).
            var filter = Task.Run(async () =>
            {
                while (!File.Exists(paths.RulesFile))
                {
                    await Task.Delay(5);
                }

                await Task.Delay(50);
                status.RulesReported(RulesEvent(PublishedGeneration(paths), applied: 1), ackTime);
            });

            var result = await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            await filter;

            Assert.True(result.Success);
            Assert.Equal(RuleState.Applied, result.State);
            Assert.Equal(ackTime, result.VerifiedUtc);
            Assert.Null(result.ErrorMessage);

            var verify = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.Equal(FirewallAction.Block, verify.EffectiveAction);
            Assert.True(verify.EnforcementVerified);
            Assert.Contains(verify.Notes, note => note.Contains("acknowledged generation 1 at", StringComparison.Ordinal));

            var capabilities = await adapter.GetCapabilitiesAsync(CancellationToken.None);
            Assert.Equal(FirewallCapabilityStatus.Available, capabilities.Status);
            Assert.Null(capabilities.Reason);
            Assert.True(capabilities.FirewallServiceRunning);
            var enforcement = capabilities.FilterEnforcement!;
            Assert.Equal(FilterEnforcementState.Verified, enforcement.State);
            Assert.True(enforcement.Connected);
            Assert.Equal(enforcement.PublishedGeneration, enforcement.AckedGeneration);
            Assert.Equal(ackTime, enforcement.LastAckUtc);
            Assert.Equal(RuleState.Applied, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);

            // Disconnect after successful enforcement: the claim is withdrawn at once.
            status.ClientDisconnected();
            var degraded = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.Null(degraded.EffectiveAction);
            Assert.False(degraded.EnforcementVerified);
            Assert.Contains(degraded.Notes, note => note.Contains("disconnected (last seen", StringComparison.Ordinal));
            var after = await adapter.GetCapabilitiesAsync(CancellationToken.None);
            Assert.Equal(FirewallCapabilityStatus.Degraded, after.Status);
            Assert.False(after.FirewallServiceRunning);
            Assert.Equal(FilterEnforcementState.Degraded, after.FilterEnforcement!.State);
            Assert.Equal(ackTime, after.FilterEnforcement.LastSeenUtc);
            Assert.Equal(RuleState.Pending, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);

            // Removal while disconnected: the table changes, enforcement of the change is unverified.
            var removed = await adapter.RemoveOwnedRuleAsync(curl.ManagedRuleId, CancellationToken.None);
            Assert.True(removed.Success);
            Assert.Equal(RuleState.Desired, removed.State);
            Assert.Null(removed.VerifiedUtc);
            Assert.Contains("awaiting AxiomFilter acknowledgement of generation 2", removed.ErrorMessage, StringComparison.Ordinal);
            Assert.Empty(FilterRulesFile.TryRead(paths.RulesFile)!.Rules);
        }
    }

    [Fact]
    public async Task AckArrivingAfterTheWait_FlipsTheRuleWithoutAReapply()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp, TimeSpan.FromMilliseconds(30));
        using (adapter)
        {
            status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            var result = await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            Assert.Equal(RuleState.Pending, result.State);

            status.RulesReported(RulesEvent(PublishedGeneration(paths), applied: 1), time.GetUtcNow());

            Assert.Equal(RuleState.Applied, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);
            Assert.Equal(FirewallAction.Block, (await adapter.VerifyAsync(curl, CancellationToken.None)).EffectiveAction);
        }
    }

    [Fact]
    public async Task RuleRejectedByTheFilter_IsFailedWithItsReason()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp, TimeSpan.FromSeconds(5));
        using (adapter)
        {
            status.ClientConnected();
            var bad = Specs.Block("/usr/bin/curl") with { RemoteAddresses = ["1.2.3"] };
            var id = bad.ManagedRuleId.ToString("D");
            var filter = Task.Run(async () =>
            {
                while (!File.Exists(paths.RulesFile))
                {
                    await Task.Delay(5);
                }

                status.RulesReported(RulesEvent(PublishedGeneration(paths), applied: 0, null, (id, "no valid remoteAddresses in [1.2.3]")), time.GetUtcNow());
            });

            var result = await adapter.UpsertOwnedRuleAsync(bad, CancellationToken.None);
            await filter;

            Assert.False(result.Success);
            Assert.Equal(RuleState.Failed, result.State);
            Assert.Equal("filter.rule_rejected", result.ErrorCode);
            Assert.Contains("no valid remoteAddresses in [1.2.3]", result.ErrorMessage, StringComparison.Ordinal);

            var verify = await adapter.VerifyAsync(bad, CancellationToken.None);
            Assert.True(verify.PresentInOs);
            Assert.Null(verify.EffectiveAction);
            Assert.False(verify.EnforcementVerified);
            Assert.Equal("no valid remoteAddresses in [1.2.3]", verify.FilterRejectionReason);
            Assert.Equal(RuleState.Failed, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);
            Assert.Equal(FilterEnforcementState.Verified, (await adapter.GetCapabilitiesAsync(CancellationToken.None)).FilterEnforcement!.State);
        }
    }

    [Fact]
    public async Task RulesFileRejectedByTheFilter_IsFailedAndTheOldGenerationStays()
    {
        using var temp = new TempDirectory();
        var (paths, time, status, adapter) = Harness(temp, TimeSpan.FromSeconds(5));
        using (adapter)
        {
            status.ClientConnected();
            status.RulesReported(RulesEvent(0), Start.AddSeconds(-1));
            var curl = Specs.Block("/usr/bin/curl");
            var filter = Task.Run(async () =>
            {
                while (!File.Exists(paths.RulesFile))
                {
                    await Task.Delay(5);
                }

                status.RulesReported(RulesEvent(0, error: "owned by uid 501, expected uid 0"), Start.AddSeconds(1));
            });

            var result = await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            await filter;

            Assert.False(result.Success);
            Assert.Equal(RuleState.Failed, result.State);
            Assert.Equal("filter.file_rejected", result.ErrorCode);
            Assert.Equal("AxiomFilter rejected rules generation 1 (owned by uid 501, expected uid 0); generation 0 stays in force.", result.ErrorMessage);

            var verify = await adapter.VerifyAsync(curl, CancellationToken.None);
            Assert.True(verify.PresentInOs);
            Assert.Null(verify.EffectiveAction);
            Assert.False(verify.EnforcementVerified);
            Assert.Contains(verify.Notes, note => note.Contains("rejected the rules file", StringComparison.Ordinal));
            Assert.Equal("owned by uid 501, expected uid 0", (await adapter.GetCapabilitiesAsync(CancellationToken.None)).FilterEnforcement!.FileError);
        }
    }

    [Fact]
    public async Task DaemonRestart_StartsPendingUntilTheFilterAcksTheRepublishedGeneration()
    {
        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var time = new ManualTimeProvider(Start);
        var curl = Specs.Block("/usr/bin/curl");

        var first = new FilterStatus();
        using (var adapter = new MacFirewallPolicyAdapter(paths, first, () => true, time, TimeSpan.Zero))
        {
            first.ClientConnected();
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            first.RulesReported(RulesEvent(1, applied: 1), time.GetUtcNow());
            Assert.Equal(RuleState.Applied, Assert.Single(await adapter.ListOwnedRulesAsync(CancellationToken.None)).State);
        }

        // New daemon process: nothing is known about the filter until it reconnects and acks.
        var restarted = new FilterStatus();
        using var again = new MacFirewallPolicyAdapter(paths, restarted, () => true, time, TimeSpan.Zero);
        Assert.Equal(RuleState.Pending, Assert.Single(await again.ListOwnedRulesAsync(CancellationToken.None)).State);
        Assert.Null((await again.VerifyAsync(curl, CancellationToken.None)).EffectiveAction);

        var republished = await again.PublishAsync(CancellationToken.None);
        Assert.Equal(2, republished);
        restarted.ClientConnected();
        restarted.Hello("1.0", 1, time.GetUtcNow()); // the filter still runs generation 1
        Assert.Equal(RuleState.Pending, Assert.Single(await again.ListOwnedRulesAsync(CancellationToken.None)).State);

        restarted.RulesReported(RulesEvent(2, applied: 1), time.GetUtcNow());
        Assert.Equal(RuleState.Applied, Assert.Single(await again.ListOwnedRulesAsync(CancellationToken.None)).State);
        Assert.Equal(FirewallAction.Block, (await again.VerifyAsync(curl, CancellationToken.None)).EffectiveAction);
    }

    [Fact]
    public async Task FilterRestart_RequiresTheRepublishedGenerationToBeAcked()
    {
        using var temp = new TempDirectory();
        var (_, time, status, adapter) = Harness(temp);
        using (adapter)
        {
            status.ClientConnected();
            var curl = Specs.Block("/usr/bin/curl");
            await adapter.UpsertOwnedRuleAsync(curl, CancellationToken.None);
            status.RulesReported(RulesEvent(1, applied: 1), time.GetUtcNow());
            Assert.True((await adapter.VerifyAsync(curl, CancellationToken.None)).EnforcementVerified);

            // Filter restarts: disconnect, reconnect; the daemon republishes on connect (FilterEventWorker).
            status.ClientDisconnected();
            status.ClientConnected();
            status.Hello("1.0", 1, time.GetUtcNow());
            var republished = await adapter.PublishAsync(CancellationToken.None);
            Assert.Equal(2, republished);
            Assert.Null((await adapter.VerifyAsync(curl, CancellationToken.None)).EffectiveAction);

            // A stale ack (the old generation) on the new connection does not verify generation 2.
            status.RulesReported(RulesEvent(1, applied: 1), time.GetUtcNow());
            Assert.Null((await adapter.VerifyAsync(curl, CancellationToken.None)).EffectiveAction);

            status.RulesReported(RulesEvent(2, applied: 1), time.GetUtcNow());
            Assert.Equal(FirewallAction.Block, (await adapter.VerifyAsync(curl, CancellationToken.None)).EffectiveAction);
        }
    }

    [Fact]
    public void OutcomeIsPureOverTheSnapshot()
    {
        var id = Guid.NewGuid();
        var ruleId = id.ToString("D");
        var report = new FilterRulesReport { Generation = 3, Applied = 1, ReceivedUtc = Start.AddSeconds(1) };

        var verified = MacFirewallPolicyAdapter.Outcome(id, "Axiom::x::OUT", ruleId, 3, Start,
            new FilterEnforcementSnapshot(FilterEnforcementState.Verified, true, 3, 3, Start.AddSeconds(1), Start.AddSeconds(1), report));
        Assert.True(verified is { Success: true, State: RuleState.Applied, VerifiedUtc: not null });

        var pending = MacFirewallPolicyAdapter.Outcome(id, null, ruleId, 3, Start,
            new FilterEnforcementSnapshot(FilterEnforcementState.Pending, true, 3, 2, Start, Start, report with { Generation = 2 }));
        Assert.True(pending is { Success: true, State: RuleState.Pending, VerifiedUtc: null, ErrorCode: null });
        Assert.Equal("awaiting AxiomFilter acknowledgement of generation 3 (last acknowledged generation 2)", pending.ErrorMessage);

        var degraded = MacFirewallPolicyAdapter.Outcome(id, null, ruleId, 3, Start,
            new FilterEnforcementSnapshot(FilterEnforcementState.Degraded, false, 3, 3, Start, Start, report));
        Assert.Equal(RuleState.Pending, degraded.State);
        Assert.EndsWith("(the network extension is disconnected)", degraded.ErrorMessage, StringComparison.Ordinal);

        var rejected = MacFirewallPolicyAdapter.Outcome(id, null, ruleId, 3, Start,
            new FilterEnforcementSnapshot(FilterEnforcementState.Verified, true, 3, 3, Start, Start,
                report with { Rejected = [new FilterRejectedRule(ruleId, "bad ports")] }));
        Assert.True(rejected is { Success: false, State: RuleState.Failed, ErrorCode: "filter.rule_rejected" });

        var fileRejected = MacFirewallPolicyAdapter.Outcome(id, null, ruleId, 3, Start,
            new FilterEnforcementSnapshot(FilterEnforcementState.Pending, true, 3, 2, Start, Start,
                report with { Generation = 2, Error = "invalid JSON", ReceivedUtc = Start.AddSeconds(1) }));
        Assert.True(fileRejected is { Success: false, State: RuleState.Failed, ErrorCode: "filter.file_rejected" });

        // A file rejection from before this publish does not fail the new generation.
        var stale = MacFirewallPolicyAdapter.Outcome(id, null, ruleId, 3, Start.AddSeconds(2),
            new FilterEnforcementSnapshot(FilterEnforcementState.Pending, true, 3, 2, Start, Start,
                report with { Generation = 2, Error = "invalid JSON", ReceivedUtc = Start.AddSeconds(1) }));
        Assert.Equal(RuleState.Pending, stale.State);
    }

    /// <summary>The daemon republishes on every filter connection so the ack is for this connection.</summary>
    [Fact]
    public async Task EventServerRunsTheConnectHookPerConnection()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var status = new FilterStatus();
        var server = new FilterEventServer(paths, new FlowTable(), status, _ => true, new ManualTimeProvider(Start));
        var connects = 0;
        server.ClientConnectedAsync = _ =>
        {
            Interlocked.Increment(ref connects);
            return Task.CompletedTask;
        };

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var run = server.RunAsync(_ => { }, cts.Token);
        try
        {
            while (!File.Exists(paths.FilterSocketPath))
            {
                await Task.Delay(20, cts.Token);
            }

            await Task.Delay(50, cts.Token);
            for (var round = 0; round < 2; round++)
            {
                using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await client.ConnectAsync(new UnixDomainSocketEndPoint(paths.FilterSocketPath), cts.Token);
                await client.SendAsync(Encoding.UTF8.GetBytes("{\"type\":\"filter.hello\",\"version\":\"1.0\",\"generation\":1,\"dropped\":0}\n"), cts.Token);
                for (var attempt = 0; attempt < 100 && Volatile.Read(ref connects) < round + 1; attempt++)
                {
                    await Task.Delay(10, cts.Token);
                }

                Assert.Equal(round + 1, Volatile.Read(ref connects));
                Assert.True(status.IsConnected);
            }

            for (var attempt = 0; attempt < 100 && status.IsConnected; attempt++)
            {
                await Task.Delay(10, cts.Token);
            }

            Assert.False(status.IsConnected);
            Assert.Equal(FilterEnforcementState.Degraded, status.Evaluate(1));
        }
        finally
        {
            await cts.CancelAsync();
            await run;
        }
    }
}
