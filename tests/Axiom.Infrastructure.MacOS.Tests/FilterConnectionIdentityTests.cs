// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Net.Sockets;
using System.Text;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.MacOS.Filter;
using Axiom.Infrastructure.MacOS.Monitoring;

namespace Axiom.Infrastructure.MacOS.Tests;

/// <summary>
/// Review 2026-11-14: an acknowledgement, error, hello or disconnect must belong to the
/// connection it arrived on. A previously accepted connection that has not seen EOF yet can still
/// send lines, and it must not change the current session's verification, generation or
/// diagnostics, nor keep it verified after the current session disconnects.
/// </summary>
public sealed class FilterConnectionIdentityTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 14, 9, 0, 0, TimeSpan.Zero);

    private static FlowEvent Rules(long generation, string? error = null, params string[] ids) =>
        FlowEventParser.TryParse(string.Create(
            CultureInfo.InvariantCulture,
            $"{{\"type\":\"filter.rules\",\"generation\":{generation},\"applied\":1,\"rejected\":[]," +
            $"\"error\":{(error is null ? "null" : "\"" + error + "\"")}," +
            $"\"ruleIds\":[{string.Join(",", ids.Select(id => "\"" + id + "\""))}],\"dropped\":0}}"))!;

    [Fact]
    public void StaleAcknowledgmentCannotVerifyTheCurrentSession()
    {
        var status = new FilterStatus();
        var stale = status.ClientConnected();
        var current = status.ClientConnected();
        status.Published(42, ["rule-1"]);

        status.RulesReported(stale, Rules(42, null, "rule-1"), Start);

        Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(42));
        Assert.False(status.Snapshot(42).RuleVerified("rule-1"));
        Assert.Null(status.Snapshot(42).Rules);

        status.RulesReported(current, Rules(42, null, "rule-1"), Start.AddSeconds(1));

        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));
        Assert.True(status.Snapshot(42).RuleVerified("rule-1"));
    }

    [Fact]
    public void StaleErrorAndOldGenerationReportsCannotDegradeTheVerifiedCurrentSession()
    {
        var status = new FilterStatus();
        var stale = status.ClientConnected();
        var current = status.ClientConnected();
        status.Published(42, ["rule-1"]);
        status.RulesReported(current, Rules(42, null, "rule-1"), Start);
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));

        status.RulesReported(stale, Rules(42, "invalid JSON"), Start.AddSeconds(1));
        status.RulesReported(stale, Rules(41, null, "rule-old"), Start.AddSeconds(2));

        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));
        Assert.True(status.Snapshot(42).RuleVerified("rule-1"));
        Assert.Null(status.Snapshot(42).Rules?.Error);
        Assert.Equal(Start, status.LastAckUtc);
    }

    [Fact]
    public void CurrentDisconnectDegradesEvenWhenAStaleConnectionIsStillOpen()
    {
        var status = new FilterStatus();
        _ = status.ClientConnected();
        var current = status.ClientConnected();
        status.Published(42, ["rule-1"]);
        status.RulesReported(current, Rules(42, null, "rule-1"), Start);
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));

        status.ClientDisconnected(current);

        Assert.Equal(FilterEnforcementState.Degraded, status.Evaluate(42));
        Assert.False(status.IsConnected);
        Assert.False(status.Snapshot(42).Connected);
    }

    [Fact]
    public void StaleDisconnectDoesNotDegradeTheVerifiedCurrentSession()
    {
        var status = new FilterStatus();
        var stale = status.ClientConnected();
        var current = status.ClientConnected();
        status.Published(42, ["rule-1"]);
        status.RulesReported(current, Rules(42, null, "rule-1"), Start);

        status.ClientDisconnected(stale);

        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));
        Assert.True(status.IsConnected);
        Assert.True(status.Snapshot(42).RuleVerified("rule-1"));
    }

    [Fact]
    public void StaleHelloAndEventsCannotOverwriteCurrentDiagnostics()
    {
        var status = new FilterStatus();
        var stale = status.ClientConnected();
        var current = status.ClientConnected();
        status.Hello(current, "current", 42, Start);
        var currentSeen = status.LastSeenUtc;

        status.Hello(stale, "stale", 7, Start.AddSeconds(1));
        status.EventSeen(stale, Start.AddSeconds(2));

        Assert.Equal("current", status.Version);
        Assert.Equal(42, status.LoadedGeneration);
        Assert.Equal(currentSeen, status.LastSeenUtc);
    }

    [Fact]
    public void StaleFlowEventsCannotChangeTheCurrentFlowTable()
    {
        using var temp = new TempDirectory();
        var status = new FilterStatus();
        var flows = new FlowTable();
        var server = new FilterEventServer(
            MacServicePaths.ForRoot(temp.Path), flows, status, _ => true, new ManualTimeProvider(Start));
        var stale = status.ClientConnected();
        var current = status.ClientConnected();

        server.Accept(new FlowEvent { Type = FlowEventType.Open, Id = "current-flow", Verdict = "allow" }, current);
        server.Accept(new FlowEvent { Type = FlowEventType.Close, Id = "current-flow" }, stale);

        var afterStaleClose = Assert.Single(flows.Capture(Start));
        Assert.Equal("Established", afterStaleClose.State);
        Assert.All(flows.Capture(Start), flow => Assert.Equal("Established", flow.State));

        server.Accept(new FlowEvent { Type = FlowEventType.Stats, Id = "current-flow", BytesIn = 100 }, stale);
        Assert.Equal(0, Assert.Single(flows.Capture(Start)).BytesIn);

        server.Accept(new FlowEvent { Type = FlowEventType.Open, Id = "stale-flow", Verdict = "block" }, stale);
        Assert.Equal(1, flows.Count);

        server.Accept(new FlowEvent { Type = FlowEventType.Stats, Id = "current-flow", BytesIn = 500 }, current);
        Assert.Equal(500, Assert.Single(flows.Capture(Start)).BytesIn);
    }

    [Fact]
    public async Task NewSessionDoesNotInheritOldReportForWaitOrOutcome()
    {
        var status = new FilterStatus();
        var stale = status.ClientConnected();
        status.Published(42, ["rule-1"]);
        status.Hello(stale, "old", 41, Start);
        status.RulesReported(stale, Rules(41, "old file error"), Start);

        var current = status.ClientConnected();
        var snapshot = status.Snapshot(42);

        Assert.Equal(FilterEnforcementState.Pending, snapshot.State);
        Assert.Null(snapshot.Rules);
        Assert.Null(snapshot.FileRejectionSince(Start));

        var wait = status.WaitForAcknowledgementAsync(42, Start, TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.False(wait.IsCompleted);

        var outcome = MacFirewallPolicyAdapter.Outcome(
            Guid.NewGuid(), null, "rule-1", 42, Start, snapshot);
        Assert.Equal(RuleState.Pending, outcome.State);
        Assert.Null(outcome.ErrorCode);

        status.RulesReported(current, Rules(42, null, "rule-1"), Start.AddSeconds(1));
        await wait.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));
    }

    /// <summary>
    /// Registration follows acceptance order even when the first worker is delayed: B, accepted
    /// later, stays current and a delayed A ack cannot replace it.
    /// </summary>
    [Fact]
    public async Task DelayedFirstAuthorizationCannotReplaceTheCurrentSession()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var status = new FilterStatus();
        using var firstAuthorization = new ManualResetEventSlim();
        using var releaseFirst = new ManualResetEventSlim();
        var authorizations = 0;
        var connected = 0;
        var server = new FilterEventServer(
            paths,
            new FlowTable(),
            status,
            _ =>
            {
                if (Interlocked.Increment(ref authorizations) == 1)
                {
                    firstAuthorization.Set();
                    return releaseFirst.Wait(TimeSpan.FromSeconds(10));
                }

                return true;
            },
            new ManualTimeProvider(Start));
        server.ClientConnectedAsync = _ =>
        {
            Interlocked.Increment(ref connected);
            return Task.CompletedTask;
        };

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var run = server.RunAsync(_ => { }, cts.Token);
        try
        {
            await WaitUntil(() => File.Exists(paths.FilterSocketPath), cts.Token);

            using var earlier = await ConnectAsync(paths.FilterSocketPath, cts.Token);
            await WaitUntil(() => firstAuthorization.IsSet, cts.Token);
            var laterConnect = ConnectAsync(paths.FilterSocketPath, cts.Token);
            await Task.Delay(100, cts.Token);
            releaseFirst.Set();
            using var later = await laterConnect;

            await WaitUntil(() => Volatile.Read(ref connected) == 2, cts.Token);
            status.Published(42, ["rule-1"]);

            await SendAsync(later, RulesJson(42), cts.Token);
            await WaitUntil(() => status.Evaluate(42) == FilterEnforcementState.Verified, cts.Token);

            await SendAsync(earlier, RulesJson(42), cts.Token);
            await WaitUntil(() => server.AcceptedEvents == 2, cts.Token);

            Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));
            Assert.Equal(2, status.Rules!.ConnectionId);
        }
        finally
        {
            releaseFirst.Set();
            await cts.CancelAsync();
            await run;
        }
    }

    /// <summary>
    /// The deterministic cases above through the real Unix-socket server: two overlapping accepted
    /// clients, a stale ack/error from A, the current B ack, then B disconnecting while A is open.
    /// </summary>
    [Fact]
    public async Task OverlapServerKeepsReportsAndDisconnectsBoundToTheirConnection()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var paths = MacServicePaths.ForRoot(temp.Path);
        var status = new FilterStatus();
        var flows = new FlowTable();
        var server = new FilterEventServer(paths, flows, status, _ => true, new ManualTimeProvider(Start));
        var accepted = 0;
        server.ClientConnectedAsync = _ =>
        {
            Interlocked.Increment(ref accepted);
            return Task.CompletedTask;
        };

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var run = server.RunAsync(_ => { }, cts.Token);
        try
        {
            await WaitUntil(() => File.Exists(paths.FilterSocketPath), cts.Token);

            using var stale = await ConnectAsync(paths.FilterSocketPath, cts.Token);
            await WaitUntil(() => Volatile.Read(ref accepted) == 1, cts.Token);
            using var current = await ConnectAsync(paths.FilterSocketPath, cts.Token);
            await WaitUntil(() => Volatile.Read(ref accepted) == 2, cts.Token);

            status.Published(42, ["rule-1"]);
            await SendAsync(stale, RulesJson(42), cts.Token);
            await WaitUntil(() => server.AcceptedEvents == 1, cts.Token);
            Assert.Equal(FilterEnforcementState.Pending, status.Evaluate(42));

            await SendAsync(current, RulesJson(42), cts.Token);
            await WaitUntil(() => status.Evaluate(42) == FilterEnforcementState.Verified, cts.Token);

            await SendAsync(stale, ErrorJson(42), cts.Token);
            await WaitUntil(() => server.AcceptedEvents == 3, cts.Token);
            Assert.Equal(FilterEnforcementState.Verified, status.Evaluate(42));

            await SendAsync(current, OpenJson("current-flow"), cts.Token);
            await WaitUntil(() => flows.Count == 1, cts.Token);
            await SendAsync(stale, "{\"type\":\"flow.close\",\"id\":\"current-flow\"}", cts.Token);
            await WaitUntil(() => server.AcceptedEvents == 5, cts.Token);
            Assert.Equal("Established", Assert.Single(flows.Capture(Start)).State);
            await SendAsync(stale, "{\"type\":\"flow.open\",\"id\":\"stale-flow\",\"verdict\":\"block\"}", cts.Token);
            await WaitUntil(() => server.AcceptedEvents == 6, cts.Token);
            Assert.Equal(1, flows.Count);

            current.Shutdown(SocketShutdown.Both);
            current.Close();
            await WaitUntil(() => status.Evaluate(42) == FilterEnforcementState.Degraded, cts.Token);
            Assert.False(status.IsConnected);

            stale.Shutdown(SocketShutdown.Both);
            stale.Close();
            await Task.Delay(100, cts.Token);
            Assert.Equal(FilterEnforcementState.Degraded, status.Evaluate(42));
        }
        finally
        {
            await cts.CancelAsync();
            await run;
        }
    }

    private static string RulesJson(long generation) =>
        $"{{\"type\":\"filter.rules\",\"generation\":{generation},\"applied\":1," +
        "\"rejected\":[],\"error\":null,\"ruleIds\":[\"rule-1\"],\"dropped\":0}";

    private static string ErrorJson(long generation) =>
        $"{{\"type\":\"filter.rules\",\"generation\":{generation},\"applied\":1," +
        "\"rejected\":[],\"error\":\"stale A error\",\"dropped\":0}";

    private static string OpenJson(string id) =>
        $"{{\"type\":\"flow.open\",\"id\":\"{id}\",\"verdict\":\"allow\"}}";

    private static async Task<Socket> ConnectAsync(string path, CancellationToken cancellationToken)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken);
        return socket;
    }

    private static async Task SendAsync(Socket socket, string line, CancellationToken cancellationToken) =>
        _ = await socket.SendAsync(Encoding.UTF8.GetBytes(line + "\n"), cancellationToken);

    private static async Task WaitUntil(Func<bool> predicate, CancellationToken cancellationToken)
    {
        while (!predicate())
        {
            await Task.Delay(10, cancellationToken);
        }
    }
}
