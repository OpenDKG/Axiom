// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class IpcRequestProcessorTests
{
    [Fact]
    public async Task Unknown_command_is_rejected_and_connection_stays_open()
    {
        var processor = Create();
        await using var stream = new MemoryStream();

        var keepOpen = await processor.ProcessAsync(stream, Envelope("axiom.exec"), "uid:1000", CancellationToken.None);

        Assert.True(keepOpen);
        var response = ReadResponse(stream);
        Assert.Equal(IpcErrorCodes.UnknownCommand, response.Error!.Code);
    }

    [Fact]
    public async Task Malformed_json_is_rejected_and_closes_the_connection()
    {
        var processor = Create();
        await using var stream = new MemoryStream();

        var keepOpen = await processor.ProcessAsync(stream, "{not-json", "uid:1000", CancellationToken.None);

        Assert.False(keepOpen);
        var response = ReadResponse(stream);
        Assert.Equal(IpcErrorCodes.InvalidRequest, response.Error!.Code);
    }

    [Fact]
    public async Task Unsupported_protocol_version_is_rejected()
    {
        var processor = Create();
        await using var stream = new MemoryStream();
        var envelope = new IpcEnvelope
        {
            Version = IpcProtocol.CurrentVersion + 1,
            Type = IpcCommandTypes.ServiceHealth,
        };

        var keepOpen = await processor.ProcessAsync(
            stream,
            JsonSerializer.Serialize(envelope, IpcJson.Options),
            "uid:1000",
            CancellationToken.None);

        Assert.True(keepOpen);
        var response = ReadResponse(stream);
        Assert.Equal(IpcErrorCodes.InvalidRequest, response.Error!.Code);
    }

    [Fact]
    public async Task Rule_apply_is_refused_while_the_write_gate_is_closed()
    {
        var processor = Create();
        await using var stream = new MemoryStream();

        var keepOpen = await processor.ProcessAsync(
            stream,
            Envelope(IpcCommandTypes.RuleApply, new RuleSpec
            {
                ManagedRuleId = Guid.NewGuid(),
                AppPath = "/usr/bin/curl",
                Direction = FirewallDirection.Outbound,
                Action = FirewallAction.Block,
                CreatedBy = "uid:1000",
            }),
            "uid:1000",
            CancellationToken.None);

        Assert.True(keepOpen);
        var response = ReadResponse(stream);
        Assert.Equal(IpcErrorCodes.NotSupported, response.Error!.Code);
    }

    [Fact]
    public async Task An_oversized_response_is_replaced_by_a_bounded_error()
    {
        var processor = new IpcRequestProcessor(
            snapshot: () => new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                SourceName = "test",
                ProcessCount = 0,
                Connections =
                [
                    new LiveConnection
                    {
                        AppDisplayName = new string('x', IpcProtocol.MaxResponseBytes + 1024),
                        AppPath = "/usr/bin/test",
                        ProcessId = 4242,
                        InterfaceName = string.Empty,
                        Protocol = TransportProtocol.Tcp,
                        LocalEndpoint = "127.0.0.1:1",
                        RemoteEndpoint = "—",
                        State = "Listen",
                        FirstObservedUtc = DateTimeOffset.UtcNow,
                        Direction = ConnectionDirection.Outbound,
                    },
                ],
            },
            health: () => new ServiceHealth
            {
                Status = "running",
                UptimeSeconds = 1,
                SourceName = "test",
                PollIntervalSeconds = 1,
                ConnectionCount = 0,
                ProcessCount = 0,
            });

        await using var stream = new MemoryStream();
        var keepOpen = await processor.ProcessAsync(
            stream,
            Envelope(IpcCommandTypes.Snapshot),
            "uid:1000",
            CancellationToken.None);

        Assert.True(keepOpen);
        Assert.InRange(stream.Length, 1, IpcProtocol.MaxResponseBytes);
        var response = ReadResponse(stream);
        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidRequest, response.Error!.Code);
    }

    [Fact]
    public void Capabilities_list_writes_only_when_the_gate_is_open()
    {
        var closed = Create().CreateCapabilities();
        Assert.False(closed.FirewallWrites);
        Assert.DoesNotContain(IpcCommandTypes.RuleApply, closed.Commands);

        var open = Create(writesEnabled: true).CreateCapabilities();
        Assert.True(open.FirewallWrites);
        Assert.Contains(IpcCommandTypes.RuleApply, open.Commands);
        Assert.Contains(IpcCommandTypes.HistoryQuery, open.Commands);
    }

    private static IpcRequestProcessor Create(bool writesEnabled = false) =>
        new(
            snapshot: () => new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "test",
            },
            health: () => new ServiceHealth
            {
                Status = "running",
                UptimeSeconds = 1,
                SourceName = "test",
                PollIntervalSeconds = 1,
                ConnectionCount = 0,
                ProcessCount = 0,
            },
            historyQuery: (_, _) => Task.FromResult(new HistoryPage
            {
                Rows = [],
                TotalCount = 0,
                DatabasePath = "/tmp/test.db",
                QueriedUtc = DateTimeOffset.UtcNow,
            }),
            ruleApply: (_, _, _) => Task.FromResult(new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = Guid.Empty,
                State = RuleState.Applied,
            }),
            firewallWritesEnabled: () => writesEnabled);

    private static string Envelope(string type, object? payload = null) =>
        JsonSerializer.Serialize(
            new IpcEnvelope
            {
                Type = type,
                Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, IpcJson.Options),
            },
            IpcJson.Options);

    private static IpcResponse ReadResponse(MemoryStream stream)
    {
        var text = Encoding.UTF8.GetString(stream.ToArray()).Trim();
        return JsonSerializer.Deserialize<IpcResponse>(text, IpcJson.Options)
            ?? throw new InvalidOperationException("No response was written.");
    }
}
