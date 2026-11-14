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
        var server = new FilterEventServer(paths, new FlowTable(), status, _ => true, new ManualTimeProvider(Start));
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
