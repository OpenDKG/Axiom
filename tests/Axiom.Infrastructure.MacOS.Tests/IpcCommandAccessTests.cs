// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class IpcCommandAccessTests
{
    /// <summary>Every command constant of the IPC contract must be classified exactly once.</summary>
    [Fact]
    public void EveryCommandIsClassifiedExactlyOnce()
    {
        var commands = typeof(IpcCommandTypes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToList();

        Assert.NotEmpty(commands);
        Assert.Equal(commands.Order(StringComparer.Ordinal), IpcCommandTypes.All.Order(StringComparer.Ordinal));

        foreach (var command in commands)
        {
            var listed = (IpcCommandAccess.PublicReadCommands.Contains(command) ? 1 : 0)
                + (IpcCommandAccess.PrivateReadCommands.Contains(command) ? 1 : 0)
                + (IpcCommandAccess.WriteCommands.Contains(command) ? 1 : 0);
            Assert.True(listed == 1, $"'{command}' must be in exactly one of PublicRead/PrivateRead/WriteCommands (found in {listed}).");
            Assert.Equal(IpcCommandAccess.ReadOnlyCommands.Contains(command), !IpcCommandAccess.IsWrite(command));
        }

        Assert.Equal(
            commands.Count,
            IpcCommandAccess.PublicReadCommands.Count + IpcCommandAccess.PrivateReadCommands.Count + IpcCommandAccess.WriteCommands.Count);
    }

    /// <summary>The public set is exactly the two health commands; everything that shows activity is private.</summary>
    [Theory]
    [InlineData("serviceHealth", IpcCommandClass.PublicRead)]
    [InlineData("capabilities", IpcCommandClass.PublicRead)]
    [InlineData("snapshot", IpcCommandClass.PrivateRead)]
    [InlineData("live.events", IpcCommandClass.PrivateRead)]
    [InlineData("history.query", IpcCommandClass.PrivateRead)]
    [InlineData("traffic.history", IpcCommandClass.PrivateRead)]
    [InlineData("diagnostics.export", IpcCommandClass.PrivateRead)]
    [InlineData("privacy.status", IpcCommandClass.PrivateRead)]
    [InlineData("threatshare.status", IpcCommandClass.PrivateRead)]
    [InlineData("protection.status", IpcCommandClass.PrivateRead)]
    [InlineData("config.get", IpcCommandClass.PrivateRead)]
    [InlineData("rules.query", IpcCommandClass.PrivateRead)]
    [InlineData("rule.verify", IpcCommandClass.PrivateRead)]
    [InlineData("rule.apply", IpcCommandClass.Write)]
    [InlineData("privacy.configure", IpcCommandClass.Write)]
    [InlineData("networkRecovery.restore", IpcCommandClass.Write)]
    [InlineData("something.new", IpcCommandClass.Write)]
    [InlineData(null, IpcCommandClass.Write)]
    public void Classification(string? command, IpcCommandClass expected)
    {
        Assert.Equal(expected, IpcCommandAccess.Classify(command));
    }

    [Fact]
    public void PublicSetIsOnlyTheHealthCommands()
    {
        Assert.Equal(["capabilities", "serviceHealth"], IpcCommandAccess.PublicReadCommands.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void CallerFlagsGateTheClasses()
    {
        var publicOnly = new IpcCaller("uid:502", false, "no writes", false, "no private reads");
        Assert.True(publicOnly.Permits(IpcCommandClass.PublicRead));
        Assert.False(publicOnly.Permits(IpcCommandClass.PrivateRead));
        Assert.False(publicOnly.Permits(IpcCommandClass.Write));
        Assert.Equal("no private reads", publicOnly.DenialMessage(IpcCommandClass.PrivateRead, "snapshot"));
        Assert.Equal("no writes", publicOnly.DenialMessage(IpcCommandClass.Write, "rule.apply"));

        var readOnly = new IpcCaller("uid:503", false, null, true);
        Assert.True(readOnly.Permits(IpcCommandClass.PrivateRead));
        Assert.False(readOnly.Permits(IpcCommandClass.Write));
        Assert.Equal("Command 'rule.apply' is not allowed for uid:503.", readOnly.DenialMessage(IpcCommandClass.Write, "rule.apply"));

        var full = IpcCaller.FullAccess("S-1-5-21-1");
        Assert.True(full.Permits(IpcCommandClass.Write));
        Assert.True(full.Permits(IpcCommandClass.PrivateRead));
    }

    [Theory]
    [InlineData("serviceHealth", false)]
    [InlineData("capabilities", false)]
    [InlineData("snapshot", false)]
    [InlineData("rules.query", false)]
    [InlineData("history.query", false)]
    [InlineData("privacy.status", false)]
    [InlineData("protection.status", false)]
    [InlineData("rule.apply", true)]
    [InlineData("rule.remove", true)]
    [InlineData("privacy.configure", true)]
    [InlineData("privacy.sources.update", true)]
    [InlineData("protection.enable", true)]
    [InlineData("protection.disable", true)]
    [InlineData("config.set", true)]
    [InlineData("threatshare.enqueue", true)]
    [InlineData("something.new", true)]
    [InlineData(null, true)]
    public void WriteClassification(string? command, bool isWrite)
    {
        Assert.Equal(isWrite, IpcCommandAccess.IsWrite(command));
    }

    // --- enforcement.status / enforcement.evaluate / enforcement.receipts (upstream #322) ---

    /// <summary>
    /// The three enforcement commands are listed explicitly (not left to the unknown-command
    /// default) and none of them is public: status carries policy counts and the policy error text,
    /// receipts carry decisions, host/agent identity and indicator references, evaluate appends to
    /// the receipt journal and the replay cache.
    /// </summary>
    [Theory]
    [InlineData("enforcement.status", IpcCommandClass.PrivateRead)]
    [InlineData("enforcement.receipts", IpcCommandClass.PrivateRead)]
    [InlineData("enforcement.evaluate", IpcCommandClass.Write)]
    public void EnforcementCommandsAreClassifiedExplicitly(string command, IpcCommandClass expected)
    {
        Assert.Contains(command, IpcCommandTypes.All);
        Assert.DoesNotContain(command, IpcCommandAccess.PublicReadCommands);
        Assert.Equal(expected, IpcCommandAccess.Classify(command));
        Assert.Contains(
            command,
            expected == IpcCommandClass.PrivateRead ? IpcCommandAccess.PrivateReadCommands : IpcCommandAccess.WriteCommands);
    }

    /// <summary>Root and the install owner use all three; a read-only caller cannot evaluate; any other uid gets none.</summary>
    [Theory]
    [InlineData("enforcement.status", true, true, true, false)]
    [InlineData("enforcement.receipts", true, true, true, false)]
    [InlineData("enforcement.evaluate", true, true, false, false)]
    public void EnforcementCommandsPerCaller(string command, bool root, bool owner, bool readOnly, bool other)
    {
        var commandClass = IpcCommandAccess.Classify(command);

        Assert.Equal(root, IpcCaller.FullAccess("uid:0").Permits(commandClass));
        Assert.Equal(owner, new IpcCaller("uid:501", true, null, true).Permits(commandClass));
        Assert.Equal(readOnly, new IpcCaller("uid:503", false, "no writes", true).Permits(commandClass));
        Assert.Equal(other, new IpcCaller("uid:502", false, "no writes", false, "no private reads").Permits(commandClass));
    }

    [Fact]
    public async Task PublicOnlyCallerNeverReachesAnEnforcementHandler()
    {
        var probe = new EnforcementProbe();
        var caller = new IpcCaller("uid:502", false, "no writes", false, "no private reads");

        var replies = await SendAsync(
            probe.Dispatcher(),
            caller,
            Envelope(IpcCommandTypes.EnforcementStatus),
            Envelope(IpcCommandTypes.EnforcementReceipts),
            Envelope(IpcCommandTypes.EnforcementEvaluate, EvaluatePayload()));

        Assert.Equal(3, replies.Count);
        Assert.All(replies, reply => Assert.False(reply.Ok));
        Assert.All(replies, reply => Assert.Equal(IpcErrorCodes.Unauthorized, reply.Error!.Code));
        Assert.Equal("no private reads", replies[0].Error!.Message);
        Assert.Equal("no private reads", replies[1].Error!.Message);
        Assert.Equal("no writes", replies[2].Error!.Message);
        Assert.Equal(0, probe.StatusCalls + probe.ReceiptsCalls + probe.EvaluateCalls);
    }

    [Fact]
    public async Task ReadOnlyCallerReadsStatusAndReceiptsButCannotEvaluate()
    {
        var probe = new EnforcementProbe();
        var caller = new IpcCaller("uid:503", false, "no writes", true);

        var replies = await SendAsync(
            probe.Dispatcher(),
            caller,
            Envelope(IpcCommandTypes.EnforcementStatus),
            Envelope(IpcCommandTypes.EnforcementReceipts),
            Envelope(IpcCommandTypes.EnforcementEvaluate, EvaluatePayload()));

        Assert.True(replies[0].Ok);
        Assert.True(replies[1].Ok);
        Assert.False(replies[2].Ok);
        Assert.Equal(IpcErrorCodes.Unauthorized, replies[2].Error!.Code);
        Assert.Equal((1, 1, 0), (probe.StatusCalls, probe.ReceiptsCalls, probe.EvaluateCalls));
    }

    /// <summary>
    /// A full-access caller (every Windows pipe client) gets what upstream's PipeServer answered:
    /// the handler result, with the authenticated actor passed to evaluate.
    /// </summary>
    [Fact]
    public async Task FullAccessCallerReachesTheHandlersWithItsActor()
    {
        var probe = new EnforcementProbe();

        var replies = await SendAsync(
            probe.Dispatcher(),
            IpcCaller.FullAccess("S-1-5-21-1"),
            Envelope(IpcCommandTypes.EnforcementStatus),
            Envelope(IpcCommandTypes.EnforcementReceipts),
            Envelope(IpcCommandTypes.EnforcementEvaluate, EvaluatePayload()),
            Envelope(IpcCommandTypes.EnforcementEvaluate));

        Assert.True(replies[0].Ok);
        Assert.Equal("rev-7", replies[0].Result!.Value.Deserialize<EnforcementStatusDto>(IpcJson.Options)!.Revision);
        Assert.True(replies[1].Ok);
        Assert.Equal(0, replies[1].Result!.Value.Deserialize<EnforcementReceiptsSnapshotDto>(IpcJson.Options)!.Total);
        Assert.True(replies[2].Ok);
        Assert.Equal("req-1", replies[2].Result!.Value.Deserialize<EnforcementVerdictDto>(IpcJson.Options)!.RequestId);
        Assert.Equal("S-1-5-21-1", probe.LastActor);
        Assert.False(replies[3].Ok);
        Assert.Equal(IpcErrorCodes.InvalidRequest, replies[3].Error!.Code);
        Assert.Equal("An enforcement evaluate payload is required.", replies[3].Error!.Message);
        Assert.Equal((1, 1, 1), (probe.StatusCalls, probe.ReceiptsCalls, probe.EvaluateCalls));
    }

    /// <summary>Without handlers (the macOS/Linux daemon) the replies are upstream's not_supported texts.</summary>
    [Fact]
    public async Task MissingEnforcementHandlersAnswerNotSupported()
    {
        var dispatcher = new IpcRequestDispatcher(
            new IpcRequestHandlers
            {
                SnapshotProvider = () => (ConnectionSnapshot?)null,
                HealthProvider = Health,
            },
            writeGateOpen: () => false);

        var replies = await SendAsync(
            dispatcher,
            IpcCaller.FullAccess("uid:0"),
            Envelope(IpcCommandTypes.EnforcementStatus),
            Envelope(IpcCommandTypes.EnforcementEvaluate, EvaluatePayload()),
            Envelope(IpcCommandTypes.EnforcementReceipts));

        Assert.All(replies, reply => Assert.Equal(IpcErrorCodes.NotSupported, reply.Error!.Code));
        Assert.Equal("Agent enforcement is not available in this build.", replies[0].Error!.Message);
        Assert.Equal("Agent enforcement is not available in this build.", replies[1].Error!.Message);
        Assert.Equal("Agent enforcement receipts are not available in this build.", replies[2].Error!.Message);
    }

    private static ServiceHealth Health() => new()
    {
        Status = "Running",
        UptimeSeconds = 1,
        SourceName = "test",
        PollIntervalSeconds = 2,
        ConnectionCount = 0,
        ProcessCount = 0,
    };

    private static string Envelope(string command, object? payload = null) => JsonSerializer.Serialize(
        new IpcEnvelope
        {
            Type = command,
            Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, IpcJson.Options),
        },
        IpcJson.Options);

    private static EnforcementEvaluateRequest EvaluatePayload() => new()
    {
        RequestId = "req-1",
        AgentId = "opencode",
        Kind = "readFile",
        Target = "/Users/owner/.ssh/id_rsa",
    };

    private static async Task<List<IpcResponse>> SendAsync(
        IpcRequestDispatcher dispatcher,
        IpcCaller caller,
        params string[] requests)
    {
        using var stream = new RequestReplyStream(string.Join('\n', requests) + "\n");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await dispatcher.HandleConnectionAsync(stream, caller, cts.Token);

        return Encoding.UTF8.GetString(stream.Written.ToArray())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options)!)
            .ToList();
    }

    /// <summary>Counts handler calls so a test can prove a denied command never reached its handler.</summary>
    private sealed class EnforcementProbe
    {
        public int StatusCalls { get; private set; }

        public int ReceiptsCalls { get; private set; }

        public int EvaluateCalls { get; private set; }

        public string? LastActor { get; private set; }

        public IpcRequestDispatcher Dispatcher() => new(
            new IpcRequestHandlers
            {
                SnapshotProvider = () => (ConnectionSnapshot?)null,
                HealthProvider = Health,
                EnforcementStatus = _ =>
                {
                    StatusCalls++;
                    return Task.FromResult(new EnforcementStatusDto
                    {
                        Enabled = true,
                        Revision = "rev-7",
                        AgentCount = 1,
                        RuleCount = 2,
                        ProtectedResourceCount = 3,
                    });
                },
                EnforcementReceipts = _ =>
                {
                    ReceiptsCalls++;
                    return Task.FromResult(new EnforcementReceiptsSnapshotDto { ChainValid = true, Total = 0, Receipts = [] });
                },
                EnforcementEvaluate = (request, actor, _) =>
                {
                    EvaluateCalls++;
                    LastActor = actor;
                    return Task.FromResult(new EnforcementVerdictDto
                    {
                        RequestId = request.RequestId,
                        Decision = "block",
                        RuleId = "rule-1",
                        ReasonCode = "test",
                        AvailableStrength = "observation",
                        EvaluatedUtc = DateTimeOffset.UnixEpoch,
                    });
                },
            },
            writeGateOpen: () => false);
    }

    /// <summary>Reads come from the prepared request bytes; writes are collected for the assertions.</summary>
    private sealed class RequestReplyStream(string requests) : Stream
    {
        private readonly MemoryStream _input = new(Encoding.UTF8.GetBytes(requests));

        public MemoryStream Written { get; } = new();

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) => Written.Write(buffer, offset, count);

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _input.Dispose();
                Written.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
