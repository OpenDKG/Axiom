// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Netpetra.Contracts.Firewall;
using Netpetra.Contracts.Ipc;
using Xunit;

namespace Netpetra.Contracts.Tests;

public sealed class IpcSerializationTests
{
    private static RuleSpec NewSpec() => new()
    {
        ManagedRuleId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
        AppPath = @"C:\Program Files\Example\example.exe",
        Direction = FirewallDirection.Outbound,
        Action = FirewallAction.Block,
        Profiles = FirewallProfile.Private | FirewallProfile.Public,
        CreatedBy = "S-1-5-21-1000",
    };

    [Fact]
    public void Envelope_round_trips_with_a_typed_payload()
    {
        var original = NewSpec();
        var payload = JsonSerializer.SerializeToElement(original, IpcJson.Options);
        var envelope = new IpcEnvelope
        {
            Type = IpcCommandTypes.RuleApply,
            Payload = payload,
        };

        var json = JsonSerializer.Serialize(envelope, IpcJson.Options);
        var parsed = JsonSerializer.Deserialize<IpcEnvelope>(json, IpcJson.Options);

        Assert.NotNull(parsed);
        Assert.Equal(IpcProtocol.CurrentVersion, parsed.Version);
        Assert.Equal(envelope.Id, parsed.Id);
        Assert.Equal(IpcCommandTypes.RuleApply, parsed.Type);

        var spec = parsed.Payload!.Value.Deserialize<RuleSpec>(IpcJson.Options);
        Assert.NotNull(spec);
        Assert.Equal(original.ManagedRuleId, spec.ManagedRuleId);
        Assert.Equal(original.AppPath, spec.AppPath);
        Assert.Equal(FirewallDirection.Outbound, spec.Direction);
        Assert.Equal(FirewallAction.Block, spec.Action);
    }

    [Fact]
    public void Property_names_are_camel_case()
    {
        var envelope = new IpcEnvelope
        {
            Type = IpcCommandTypes.Snapshot,
            Payload = JsonSerializer.SerializeToElement(new { }, IpcJson.Options),
        };

        var json = JsonSerializer.Serialize(envelope, IpcJson.Options);

        Assert.Contains("\"requestedAtUtc\"", json, StringComparison.Ordinal);
        Assert.Contains("\"version\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"RequestedAtUtc\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_required_properties_fail_deserialization()
    {
        Assert.ThrowsAny<JsonException>(() =>
            JsonSerializer.Deserialize<IpcEnvelope>("{\"version\":1}", IpcJson.Options));

        Assert.ThrowsAny<JsonException>(() =>
            JsonSerializer.Deserialize<RuleSpec>(
                "{\"managedRuleId\":\"11111111-2222-3333-4444-555555555555\",\"appPath\":\"C:\\\\x.exe\"}",
                IpcJson.Options));
    }

    [Fact]
    public void Rule_spec_requires_an_explicit_direction_action_and_actor()
    {
        var json = JsonSerializer.Serialize(NewSpec(), IpcJson.Options);

        Assert.Contains("\"direction\":\"outbound\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"action\":\"block\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"createdBy\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Malformed_service_response_is_reported_as_ipc_error()
    {
        var pipeName = "netpetra-contract-test-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync();
        var client = new IpcPipeClient(
            pipeName,
            connectTimeout: TimeSpan.FromSeconds(2),
            requestTimeout: TimeSpan.FromSeconds(2));

        var request = client.SendAsync<object>(
            IpcCommandTypes.ServiceHealth,
            payload: null,
            CancellationToken.None);

        await accept;
        var reader = new IpcLineReader(server);
        await reader.ReadLineAsync(IpcProtocol.MaxMessageBytes, CancellationToken.None);
        await server.WriteAsync(Encoding.UTF8.GetBytes("{not-json\n"));
        await server.FlushAsync();

        var exception = await Assert.ThrowsAsync<IpcClientException>(() => request);
        Assert.Equal(IpcErrorCodes.InvalidRequest, exception.Code);
    }
}
