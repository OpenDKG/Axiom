// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Ipc;
using Axiom.Infrastructure.Windows.Ipc;
using Axiom.Service.Hosting.Ipc;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

/// <summary>
/// The caller's permissions are decided by the transport and written out in full: neither
/// <see cref="IpcCaller.CanWrite"/> nor <see cref="IpcCaller.CanReadPrivate"/> has a default, so a
/// restricted caller cannot receive private read by omission. The dispatcher tests below run every
/// <see cref="IpcCommandTypes"/> constant through a dispatcher whose handlers count their calls, so a
/// denial is proven by the reply and by the handler never running.
/// </summary>
public sealed class IpcCallerPermissionTests
{
    private const string NoWrites = "no writes";

    private const string NoPrivateReads = "no private reads";

    /// <summary>Every public constructor names both permissions and gives neither a default.</summary>
    [Fact]
    public void CallerConstructorHasNoOptionalPermissionParameters()
    {
        var constructors = typeof(IpcCaller).GetConstructors();
        Assert.NotEmpty(constructors);

        foreach (var constructor in constructors.Where(ctor => ctor.GetParameters().All(p => p.ParameterType != typeof(IpcCaller))))
        {
            var parameters = constructor.GetParameters();
            foreach (var name in new[] { nameof(IpcCaller.CanWrite), nameof(IpcCaller.CanReadPrivate) })
            {
                var parameter = Assert.Single(parameters, p => p.Name == name);
                Assert.Equal(typeof(bool), parameter.ParameterType);
                Assert.False(parameter.HasDefaultValue, $"{constructor}: '{name}' must not have a default value.");
                Assert.False(parameter.IsOptional, $"{constructor}: '{name}' must not be optional.");
            }
        }
    }

    /// <summary>A caller built with both permissions false holds only <see cref="IpcCommandClass.PublicRead"/>.</summary>
    [Fact]
    public void RestrictedCallerHoldsOnlyPublicRead()
    {
        var caller = PublicOnly();

        Assert.False(caller.CanWrite);
        Assert.False(caller.CanReadPrivate);
        Assert.True(caller.Permits(IpcCommandClass.PublicRead));
        Assert.False(caller.Permits(IpcCommandClass.PrivateRead));
        Assert.False(caller.Permits(IpcCommandClass.Write));
    }

    /// <summary>A public-only caller gets the redacted health and the capability list, nothing else.</summary>
    [Fact]
    public async Task PublicOnlyCallerGetsRedactedHealthAndCapabilities()
    {
        var probe = new HandlerProbe();

        var replies = await SendAsync(
            probe.Dispatcher(writeGateOpen: true),
            PublicOnly(),
            Envelope(IpcCommandTypes.ServiceHealth),
            Envelope(IpcCommandTypes.Capabilities));

        Assert.Equal(2, replies.Count);
        Assert.All(replies, reply => Assert.True(reply.Ok));

        var health = replies[0].Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options)!;
        Assert.Equal("Running", health.Status);
        Assert.Equal(0, health.ConnectionCount);
        Assert.Equal(0, health.ProcessCount);
        Assert.Null(health.LastCaptureUtc);
        Assert.Null(health.LastError);
        Assert.Equal([IpcCommandAccess.HealthRedactedNote], health.Limitations);
        Assert.NotNull(replies[1].Result);
        Assert.Equal(0, probe.HandlerCalls);
    }

    /// <summary>Every private-read command is refused for a public-only caller and never reaches its handler.</summary>
    [Fact]
    public async Task PublicOnlyCallerIsDeniedEveryPrivateRead()
    {
        var probe = new HandlerProbe();
        var commands = IpcCommandAccess.PrivateReadCommands.Order(StringComparer.Ordinal).ToList();

        var replies = await SendAsync(
            probe.Dispatcher(writeGateOpen: true),
            PublicOnly(),
            commands.Select(command => Envelope(command)).ToArray());

        Assert.Equal(commands.Count, replies.Count);
        Assert.All(replies, reply =>
        {
            Assert.False(reply.Ok);
            Assert.Equal(IpcErrorCodes.Unauthorized, reply.Error!.Code);
            Assert.Equal(NoPrivateReads, reply.Error.Message);
        });
        Assert.Equal(0, probe.HandlerCalls);
        Assert.Equal(0, probe.SnapshotCalls);
    }

    /// <summary>
    /// Every write command is refused for a public-only caller and for a caller with private read
    /// but no write, even with the firewall write gate open; no write handler runs.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerWithoutWriteIsDeniedEveryWrite(bool canReadPrivate)
    {
        var probe = new HandlerProbe();
        var caller = new IpcCaller(
            "uid:502",
            CanWrite: false,
            CanReadPrivate: canReadPrivate,
            WriteDenialReason: NoWrites,
            ReadDenialReason: NoPrivateReads);
        var commands = IpcCommandAccess.WriteCommands.Order(StringComparer.Ordinal).ToList();

        var replies = await SendAsync(
            probe.Dispatcher(writeGateOpen: true),
            caller,
            commands.Select(command => Envelope(command)).ToArray());

        Assert.Equal(commands.Count, replies.Count);
        Assert.All(replies, reply =>
        {
            Assert.False(reply.Ok);
            Assert.Equal(IpcErrorCodes.Unauthorized, reply.Error!.Code);
            Assert.Equal(NoWrites, reply.Error.Message);
        });
        Assert.Equal(0, probe.HandlerCalls);
    }

    /// <summary>A caller with private read but no write gets the unredacted health.</summary>
    [Fact]
    public async Task PrivateReaderGetsFullHealth()
    {
        var probe = new HandlerProbe();
        var caller = new IpcCaller("uid:503", CanWrite: false, CanReadPrivate: true);

        var replies = await SendAsync(probe.Dispatcher(writeGateOpen: true), caller, Envelope(IpcCommandTypes.ServiceHealth));

        var health = Assert.Single(replies).Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options)!;
        Assert.Equal(5, health.ConnectionCount);
        Assert.Equal(3, health.ProcessCount);
        Assert.DoesNotContain(IpcCommandAccess.HealthRedactedNote, health.Limitations);
    }

    /// <summary>
    /// The Windows pipe's caller (the SID the DACL and the SID re-check admitted) passes the access
    /// check for every command constant: no reply is <c>unauthorized</c>, and the handlers run.
    /// </summary>
    [Fact]
    public async Task AuthenticatedWindowsSidCallerPassesTheCheckForEveryCommand()
    {
        var probe = new HandlerProbe();
        var caller = WindowsPipeCaller.Authenticated("S-1-5-21-1");
        Assert.True(caller.CanWrite);
        Assert.True(caller.CanReadPrivate);

        var commands = IpcCommandTypes.All.Order(StringComparer.Ordinal).ToList();
        var replies = await SendAsync(
            probe.Dispatcher(writeGateOpen: true),
            caller,
            commands.Select(command => Envelope(command)).ToArray());

        Assert.Equal(commands.Count, replies.Count);
        for (var i = 0; i < commands.Count; i++)
        {
            Assert.True(
                replies[i].Ok || replies[i].Error!.Code != IpcErrorCodes.Unauthorized,
                $"'{commands[i]}' was refused for the authenticated SID.");
        }

        Assert.Equal(1, probe.SnapshotCalls);
        Assert.True(probe.HandlerCalls > 0);
    }

    /// <summary>
    /// An unknown command counts as a write: refused before dispatch for a caller without write, and
    /// answered <c>unknown_command</c> (no handler) for a caller with every class.
    /// </summary>
    [Theory]
    [InlineData("something.new")]
    [InlineData("rule.apply ")]
    [InlineData("SNAPSHOT")]
    [InlineData("")]
    public async Task UnknownCommandIsDeniedByDefault(string command)
    {
        Assert.Equal(IpcCommandClass.Write, IpcCommandAccess.Classify(command));

        var probe = new HandlerProbe();
        var readOnly = new IpcCaller("uid:503", CanWrite: false, CanReadPrivate: true, WriteDenialReason: NoWrites);
        var denied = Assert.Single(await SendAsync(probe.Dispatcher(writeGateOpen: true), readOnly, Envelope(command)));
        Assert.Equal(IpcErrorCodes.Unauthorized, denied.Error!.Code);

        var full = Assert.Single(await SendAsync(
            probe.Dispatcher(writeGateOpen: true),
            WindowsPipeCaller.Authenticated("S-1-5-21-1"),
            Envelope(command)));
        Assert.Equal(IpcErrorCodes.UnknownCommand, full.Error!.Code);

        Assert.Equal(0, probe.HandlerCalls);
        Assert.Equal(0, probe.SnapshotCalls);
    }

    // --- bounded request limits on the dispatcher path ---

    /// <summary>A request line over <see cref="IpcProtocol.MaxMessageBytes"/> ends the connection unparsed.</summary>
    [Fact]
    public async Task OversizedRequestClosesTheConnectionBeforeAnyHandler()
    {
        var probe = new HandlerProbe();
        var oversized = new string('a', IpcProtocol.MaxMessageBytes + 1);

        var replies = await SendAsync(
            probe.Dispatcher(writeGateOpen: true),
            WindowsPipeCaller.Authenticated("S-1-5-21-1"),
            oversized,
            Envelope(IpcCommandTypes.Snapshot));

        var reply = Assert.Single(replies);
        Assert.Equal(IpcErrorCodes.MessageTooLarge, reply.Error!.Code);
        Assert.Equal(0, probe.SnapshotCalls);
        Assert.Equal(0, probe.HandlerCalls);
    }

    /// <summary>More than <see cref="IpcRequestDispatcher.MaxRequestsPerSecond"/> requests in a second end the connection.</summary>
    [Fact]
    public async Task RequestFloodHitsTheRateLimit()
    {
        var probe = new HandlerProbe();
        var requests = Enumerable.Repeat(Envelope(IpcCommandTypes.Snapshot), IpcRequestDispatcher.MaxRequestsPerSecond * 3).ToArray();

        var replies = await SendAsync(probe.Dispatcher(writeGateOpen: true), WindowsPipeCaller.Authenticated("S-1-5-21-1"), requests);

        Assert.True(replies.Count < requests.Length, $"{replies.Count} replies for {requests.Length} requests.");
        var last = replies[^1];
        Assert.Equal(IpcErrorCodes.InvalidRequest, last.Error!.Code);
        Assert.Equal("Rate limit exceeded.", last.Error.Message);
        Assert.Equal(replies.Count - 1, probe.SnapshotCalls);
    }

    /// <summary>A connection that sends nothing is closed after <see cref="IpcRequestDispatcher.IdleTimeout"/>.</summary>
    [Fact]
    public async Task SilentConnectionIsClosedAfterTheIdleTimeout()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), IpcRequestDispatcher.IdleTimeout);

        var probe = new HandlerProbe();
        using var stream = new SilentStream();
        using var outer = new CancellationTokenSource(IpcRequestDispatcher.IdleTimeout * 3);
        var clock = Stopwatch.StartNew();

        await probe.Dispatcher(writeGateOpen: true)
            .HandleConnectionAsync(stream, WindowsPipeCaller.Authenticated("S-1-5-21-1"), outer.Token);

        clock.Stop();
        Assert.False(outer.IsCancellationRequested, "The connection outlived three idle timeouts.");
        Assert.InRange(clock.Elapsed, IpcRequestDispatcher.IdleTimeout - TimeSpan.FromSeconds(1), IpcRequestDispatcher.IdleTimeout * 2);
        Assert.Equal(0, stream.BytesWritten);
    }

    private static IpcCaller PublicOnly() => new(
        "uid:502",
        CanWrite: false,
        CanReadPrivate: false,
        WriteDenialReason: NoWrites,
        ReadDenialReason: NoPrivateReads);

    private static ServiceHealth Health() => new()
    {
        Status = "Running",
        UptimeSeconds = 1,
        SourceName = "test",
        PollIntervalSeconds = 2,
        LastCaptureUtc = DateTimeOffset.UnixEpoch,
        ConnectionCount = 5,
        ProcessCount = 3,
        Limitations = ["adapter C:\\private\\path"],
        LastError = "private error text",
    };

    private static string Envelope(string command) => JsonSerializer.Serialize(
        new IpcEnvelope { Type = command },
        IpcJson.Options);

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

    /// <summary>
    /// Every optional handler is set and counts its call, then fails (the dispatcher answers
    /// <c>internal_error</c>); a test only needs to know whether a handler was reached.
    /// </summary>
    private sealed class HandlerProbe
    {
        private int _handlerCalls;

        private int _snapshotCalls;

        public int HandlerCalls => _handlerCalls;

        public int SnapshotCalls => _snapshotCalls;

        public IpcRequestDispatcher Dispatcher(bool writeGateOpen) => new(
            new IpcRequestHandlers
            {
                SnapshotProvider = () =>
                {
                    Interlocked.Increment(ref _snapshotCalls);
                    return null;
                },
                HealthProvider = Health,
                HistoryQuery = (_, _) => Reached<Axiom.Contracts.History.HistoryPage>(),
                ThroughputHistory = (_, _) => Reached<Axiom.Contracts.Monitoring.ThroughputHistory>(),
                RulesQuery = _ => Reached<FirewallRulesSnapshot>(),
                RuleApply = (_, _, _) => Reached<Axiom.Contracts.Firewall.RuleApplyResult>(),
                RuleRemove = (_, _, _) => Reached<Axiom.Contracts.Firewall.RuleApplyResult>(),
                RuleVerify = (_, _) => Reached<Axiom.Contracts.Firewall.EffectiveRuleReport>(),
                PrivacyStatus = _ => Reached<Axiom.Contracts.Privacy.PrivacyShieldStatus>(),
                PrivacyConfigure = (_, _) => Reached<Axiom.Contracts.Privacy.PrivacyShieldStatus>(),
                PrivacySourcesUpdate = _ => Reached<Axiom.Contracts.Privacy.PrivacyShieldStatus>(),
                PrivacyHistoryClear = _ => Reached<Axiom.Contracts.Privacy.PrivacyShieldStatus>(),
                ProtectionStatus = _ => Reached<Axiom.Contracts.Protection.ProtectionStatus>(),
                ProtectionEnable = (_, _, _) => Reached<Axiom.Contracts.Protection.ProtectionStatus>(),
                ProtectionDisable = (_, _) => Reached<Axiom.Contracts.Protection.ProtectionStatus>(),
                ProtectionDecide = (_, _, _) => Reached<Axiom.Contracts.Protection.ProtectionStatus>(),
                ProtectionDismiss = (_, _) => Reached<Axiom.Contracts.Protection.ProtectionStatus>(),
                ProtectionLockdown = (_, _, _) => Reached<Axiom.Contracts.Protection.ProtectionStatus>(),
                ThreatShareStatus = _ => Reached<Axiom.Contracts.Threat.ThreatShareQueueStatus>(),
                ThreatShareEnqueue = (_, _) => Reached<Axiom.Contracts.Threat.ThreatShareQueueStatus>(),
                ThreatShareDismiss = (_, _) => Reached<Axiom.Contracts.Threat.ThreatShareQueueStatus>(),
                ThreatShareRecord = (_, _) => Reached<Axiom.Contracts.Threat.ThreatShareQueueStatus>(),
                NetworkRecoveryCapture = (_, _) => Reached<Axiom.Contracts.NetworkRecovery.NetworkRecoveryCaptureResult>(),
                NetworkRecoveryRestore = (_, _) => Reached<Axiom.Contracts.NetworkRecovery.NetworkRecoveryRestoreResult>(),
                EnforcementStatus = _ => Reached<EnforcementStatusDto>(),
                EnforcementEvaluate = (_, _, _) => Reached<EnforcementVerdictDto>(),
                EnforcementReceipts = _ => Reached<EnforcementReceiptsSnapshotDto>(),
            },
            writeGateOpen: () => writeGateOpen);

        private Task<T> Reached<T>()
        {
            Interlocked.Increment(ref _handlerCalls);
            return Task.FromException<T>(new InvalidOperationException("handler reached"));
        }
    }

    /// <summary>A client that connects and never sends: every read waits until it is cancelled.</summary>
    private sealed class SilentStream : Stream
    {
        public long BytesWritten { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => BytesWritten += count;

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
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
