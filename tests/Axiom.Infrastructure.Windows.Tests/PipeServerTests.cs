// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.Windows.Ipc;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class PipeSecurityTests
{
    [Fact]
    public void Acl_allows_the_current_user_and_denies_network_and_anonymous()
    {
        var currentSid = WindowsIdentity.GetCurrent().User!.Value;

        var security = PipeSecurityFactory.Create(currentSid);

        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .ToList();

        Assert.Contains(rules, rule =>
            rule.AccessControlType == System.Security.AccessControl.AccessControlType.Allow &&
            rule.IdentityReference.Value == currentSid);

        Assert.Contains(rules, rule =>
            rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny &&
            rule.IdentityReference.Value == new SecurityIdentifier(WellKnownSidType.NetworkSid, null).Value);

        Assert.Contains(rules, rule =>
            rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny &&
            rule.IdentityReference.Value == new SecurityIdentifier(WellKnownSidType.AnonymousSid, null).Value);
    }
}

public sealed class PipeServerTests : IAsyncLifetime
{
    private ServerHost? _host;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }
    }

    [Fact]
    public async Task Health_request_returns_a_running_service()
    {
        _host = await ServerHost.StartAsync();

        var response = await SendAsync(_host.PipeName, IpcCommandTypes.ServiceHealth);

        Assert.True(response.Ok);
        var health = response.Result!.Value.Deserialize<ServiceHealth>(IpcJson.Options);
        Assert.NotNull(health);
        Assert.Equal("running", health.Status);
        Assert.Equal("test-source", health.SourceName);
    }

    [Fact]
    public async Task Capabilities_report_no_firewall_writes()
    {
        _host = await ServerHost.StartAsync();

        var response = await SendAsync(_host.PipeName, IpcCommandTypes.Capabilities);

        Assert.True(response.Ok);
        var capabilities = response.Result!.Value.Deserialize<ServiceCapabilities>(IpcJson.Options);
        Assert.NotNull(capabilities);
        Assert.False(capabilities.FirewallWrites);
        Assert.Contains(IpcCommandTypes.Snapshot, capabilities.Commands);
    }

    [Fact]
    public async Task Snapshot_returns_the_cached_rows()
    {
        _host = await ServerHost.StartAsync();

        var response = await SendAsync(_host.PipeName, IpcCommandTypes.Snapshot);

        Assert.True(response.Ok);
        var snapshot = response.Result!.Value.Deserialize<ConnectionSnapshot>(IpcJson.Options);
        Assert.NotNull(snapshot);
        Assert.Single(snapshot.Connections);
        Assert.Equal(4242, snapshot.Connections[0].ProcessId);
    }

    [Fact]
    public async Task Unknown_command_is_rejected()
    {
        _host = await ServerHost.StartAsync();

        var response = await SendAsync(_host.PipeName, "not.a.command");

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.UnknownCommand, response.Error!.Code);
    }

    [Fact]
    public async Task Firewall_write_command_is_not_supported()
    {
        _host = await ServerHost.StartAsync();

        var response = await SendAsync(_host.PipeName, IpcCommandTypes.RuleApply);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.NotSupported, response.Error!.Code);
    }

    [Fact]
    public async Task Oversized_message_is_rejected_before_parsing()
    {
        _host = await ServerHost.StartAsync();

        using var pipe = new NamedPipeClientStream(".", _host.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await pipe.ConnectAsync(3000, timeout.Token);

        var payload = new string('x', IpcProtocol.MaxMessageBytes + 64);
        var bytes = Encoding.UTF8.GetBytes(payload + "\n");
        await pipe.WriteAsync(bytes, timeout.Token);
        await pipe.FlushAsync(timeout.Token);

        var line = await IpcLineProtocol.ReadLineAsync(pipe, IpcProtocol.MaxResponseBytes, timeout.Token);

        Assert.NotNull(line);
        var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options);
        Assert.NotNull(response);
        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.MessageTooLarge, response.Error!.Code);
    }

    [Fact]
    public async Task A_client_with_a_different_sid_is_disconnected()
    {
        var otherSid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        _host = await ServerHost.StartAsync(allowedSid: otherSid);

        using var pipe = new NamedPipeClientStream(".", _host.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await pipe.ConnectAsync(3000, timeout.Token);

        var envelope = new IpcEnvelope { Type = IpcCommandTypes.ServiceHealth };

        try
        {
            await IpcLineProtocol.WriteLineAsync(
                pipe,
                JsonSerializer.Serialize(envelope, IpcJson.Options),
                timeout.Token);

            var line = await IpcLineProtocol.ReadLineAsync(pipe, IpcProtocol.MaxResponseBytes, timeout.Token);

            // The server closes the pipe without a response for an unauthorized SID.
            Assert.Null(line);
        }
        catch (IOException)
        {
            // Acceptable: the rejection closes the pipe before the client finishes writing.
        }
    }

    [Fact]
    public async Task Snapshot_larger_than_the_request_limit_is_returned()
    {
        var big = new ConnectionSnapshot
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            SourceName = "test-source",
            ProcessCount = 3000,
            Connections = Enumerable.Range(1, 3000).Select(index => new LiveConnection
            {
                AppDisplayName = "big.exe",
                AppPath = @"C:\Program Files\Big\big.exe",
                ProcessId = index,
                Protocol = TransportProtocol.Tcp,
                LocalEndpoint = $"192.0.2.10:{40000 + index}",
                RemoteEndpoint = $"203.0.113.20:{40000 + index}",
                State = "Established",
                Direction = ConnectionDirection.Outbound,
                InterfaceName = string.Empty,
                FirstObservedUtc = DateTimeOffset.UtcNow,
                Quality = DataQuality.Observed,
            }).ToList(),
        };

        _host = await ServerHost.StartAsync(snapshot: big);

        var response = await SendAsync(_host.PipeName, IpcCommandTypes.Snapshot);

        Assert.True(response.Ok);
        var snapshot = response.Result!.Value.Deserialize<ConnectionSnapshot>(IpcJson.Options);
        Assert.NotNull(snapshot);
        Assert.Equal(3000, snapshot.Connections.Count);
    }

    [Fact]
    public async Task Rules_query_returns_capability_and_owned_rules()
    {
        var rule = new ManagedRule
        {
            ManagedRuleId = Guid.NewGuid(),
            OsRuleName = "Axiom::11111111-1111-1111-1111-111111111111::OUT",
            State = RuleState.Applied,
            Spec = new RuleSpec
            {
                ManagedRuleId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                AppPath = @"C:\test.exe",
                Direction = FirewallDirection.Outbound,
                Action = FirewallAction.Block,
                Profiles = FirewallProfile.All,
                CreatedBy = "test",
            },
        };

        var firewall = new FirewallRulesSnapshot
        {
            Capability = new FirewallCapabilityReport
            {
                Status = FirewallCapabilityStatus.Available,
                ManagedRulesReadable = true,
                ManagedRuleCount = 1,
            },
            Rules = [rule],
        };

        _host = await ServerHost.StartAsync(firewall: firewall);

        var response = await SendAsync(_host.PipeName, IpcCommandTypes.RulesQuery);

        Assert.True(response.Ok);
        var result = response.Result!.Value.Deserialize<FirewallRulesSnapshot>(IpcJson.Options);
        Assert.NotNull(result);
        Assert.Equal(FirewallCapabilityStatus.Available, result.Capability.Status);
        Assert.Single(result.Rules);
        Assert.Equal(rule.OsRuleName, result.Rules[0].OsRuleName);
    }

    [Fact]
    public async Task Rule_apply_is_rejected_when_writes_are_disabled()
    {
        _host = await ServerHost.StartAsync();

        var response = await SendAsync(_host.PipeName, IpcCommandTypes.RuleApply);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.NotSupported, response.Error!.Code);
    }

    [Fact]
    public async Task Recovery_commands_are_not_supported_without_a_handler()
    {
        _host = await ServerHost.StartAsync();

        var capture = await SendAsync(_host.PipeName, IpcCommandTypes.NetworkRecoveryCapture);
        var restore = await SendAsync(_host.PipeName, IpcCommandTypes.NetworkRecoveryRestore);

        Assert.False(capture.Ok);
        Assert.Equal(IpcErrorCodes.NotSupported, capture.Error!.Code);
        Assert.False(restore.Ok);
        Assert.Equal(IpcErrorCodes.NotSupported, restore.Error!.Code);
    }

    [Fact]
    public async Task Recovery_commands_reject_client_supplied_state()
    {
        _host = await ServerHost.StartAsync(
            networkRecoveryCapture: (_, _) => Task.FromResult(Captured()),
            networkRecoveryRestore: (_, _) => Task.FromResult(Restored()));

        var capture = await SendAsync(
            _host.PipeName,
            IpcCommandTypes.NetworkRecoveryCapture,
            new { adapters = "8.8.8.8" });
        var restore = await SendAsync(
            _host.PipeName,
            IpcCommandTypes.NetworkRecoveryRestore,
            new { servers = "8.8.8.8" });

        Assert.False(capture.Ok);
        Assert.Equal(IpcErrorCodes.InvalidRequest, capture.Error!.Code);
        Assert.False(restore.Ok);
        Assert.Equal(IpcErrorCodes.InvalidRequest, restore.Error!.Code);
    }

    [Fact]
    public async Task Recovery_commands_return_typed_results_and_are_advertised()
    {
        var captureCalled = false;
        var restoreCalled = false;
        _host = await ServerHost.StartAsync(
            networkRecoveryCapture: (actor, _) =>
            {
                captureCalled = actor.Length > 0;
                return Task.FromResult(Captured());
            },
            networkRecoveryRestore: (actor, _) =>
            {
                restoreCalled = actor.Length > 0;
                return Task.FromResult(Restored());
            });

        var capabilities = await SendAsync(_host.PipeName, IpcCommandTypes.Capabilities);
        var captured = await SendAsync(_host.PipeName, IpcCommandTypes.NetworkRecoveryCapture);
        var restored = await SendAsync(_host.PipeName, IpcCommandTypes.NetworkRecoveryRestore);

        var advertised = capabilities.Result!.Value.Deserialize<ServiceCapabilities>(IpcJson.Options)!;
        Assert.Contains(IpcCommandTypes.NetworkRecoveryCapture, advertised.Commands);
        Assert.Contains(IpcCommandTypes.NetworkRecoveryRestore, advertised.Commands);

        Assert.True(captured.Ok);
        Assert.Equal(
            NetworkRecoveryStatus.Succeeded,
            captured.Result!.Value.Deserialize<NetworkRecoveryCaptureResult>(IpcJson.Options)!.Status);
        Assert.True(restored.Ok);
        Assert.True(restored.Result!.Value.Deserialize<NetworkRecoveryRestoreResult>(IpcJson.Options)!.Verified);
        Assert.True(captureCalled);
        Assert.True(restoreCalled);
    }

    [Fact]
    public async Task Capabilities_advertise_enforcement_commands_when_handlers_are_registered()
    {
        var pipeName = $"Axiom.Test.{Guid.NewGuid():N}";
        var sid = WindowsIdentity.GetCurrent().User!.Value;
        var health = new ServiceHealth
        {
            Status = "running",
            UptimeSeconds = 1,
            SourceName = "test",
            PollIntervalSeconds = 1,
            ConnectionCount = 0,
            ProcessCount = 0,
        };

        var server = new PipeServer(
            pipeName,
            sid,
            () => null,
            () => health,
            enforcementStatus: _ => Task.FromResult(new EnforcementStatusDto
            {
                Enabled = false,
                Revision = "0",
                AgentCount = 0,
                RuleCount = 0,
                ProtectedResourceCount = 0,
            }),
            enforcementEvaluate: (req, _, _) => Task.FromResult(new EnforcementVerdictDto
            {
                RequestId = req.RequestId,
                Decision = "audit",
                RuleId = "default",
                ReasonCode = "monitor",
                AvailableStrength = "observation",
                EvaluatedUtc = DateTimeOffset.UtcNow,
            }),
            enforcementReceipts: _ => Task.FromResult(new EnforcementReceiptsSnapshotDto
            {
                ChainValid = true,
                Total = 0,
                Receipts = [],
            }));

        using var cts = new CancellationTokenSource();
        var run = server.RunAsync(cts.Token);
        for (var i = 0; i < 60; i++)
        {
            if (Directory.GetFiles(@"\\.\pipe\").Any(p => string.Equals(Path.GetFileName(p), pipeName, StringComparison.OrdinalIgnoreCase)))
            {
                break;
            }

            await Task.Delay(50);
        }

        try
        {
            var capsResponse = await SendAsync(pipeName, IpcCommandTypes.Capabilities);
            Assert.True(capsResponse.Ok);
            var caps = capsResponse.Result!.Value.Deserialize<ServiceCapabilities>(IpcJson.Options)!;
            Assert.Contains(IpcCommandTypes.EnforcementStatus, caps.Commands);
            Assert.Contains(IpcCommandTypes.EnforcementEvaluate, caps.Commands);
            Assert.Contains(IpcCommandTypes.EnforcementReceipts, caps.Commands);
        }
        finally
        {
            await cts.CancelAsync();
            try
            {
                await run.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (TimeoutException)
            {
            }
        }
    }

    private static NetworkRecoveryCaptureResult Captured() => new()
    {
        Status = NetworkRecoveryStatus.Succeeded,
        CapturedUtc = DateTimeOffset.UtcNow,
        AdapterCount = 1,
        RuleCount = 1,
        Persisted = true,
    };

    private static NetworkRecoveryRestoreResult Restored() => new()
    {
        Status = NetworkRecoveryStatus.Succeeded,
        AdaptersRestored = 1,
        AdaptersVerified = 1,
        RulesRemoved = 1,
        RulesVerifiedAbsent = 1,
        Verified = true,
        CompletedUtc = DateTimeOffset.UtcNow,
    };

    private static async Task<IpcResponse> SendAsync(string pipeName, string command, object? payload = null)
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await pipe.ConnectAsync(3000, timeout.Token);

        var envelope = new IpcEnvelope
        {
            Type = command,
            Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, IpcJson.Options),
        };
        await IpcLineProtocol.WriteLineAsync(
            pipe,
            JsonSerializer.Serialize(envelope, IpcJson.Options),
            timeout.Token);

        var line = await IpcLineProtocol.ReadLineAsync(pipe, IpcProtocol.MaxResponseBytes, timeout.Token);
        Assert.NotNull(line);

        var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options);
        Assert.NotNull(response);
        return response;
    }

    private sealed class ServerHost : IAsyncDisposable
    {
        private readonly CancellationTokenSource _cancellation = new();

        private readonly Task _run;

        private ServerHost(string pipeName, PipeServer server)
        {
            PipeName = pipeName;
            _run = server.RunAsync(_cancellation.Token);
        }

        public string PipeName { get; }

        public static async Task<ServerHost> StartAsync(
            string? allowedSid = null,
            ConnectionSnapshot? snapshot = null,
            FirewallRulesSnapshot? firewall = null,
            Func<string, CancellationToken, Task<NetworkRecoveryCaptureResult>>? networkRecoveryCapture = null,
            Func<string, CancellationToken, Task<NetworkRecoveryRestoreResult>>? networkRecoveryRestore = null)
        {
            var pipeName = $"Axiom.Test.{Guid.NewGuid():N}";
            var sid = allowedSid ?? WindowsIdentity.GetCurrent().User!.Value;

            snapshot ??= new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                SourceName = "test-source",
                ProcessCount = 1,
                Connections =
                [
                    new LiveConnection
                    {
                        AppDisplayName = "test.exe",
                        AppPath = @"C:\test.exe",
                        ProcessId = 4242,
                        Protocol = TransportProtocol.Tcp,
                        LocalEndpoint = "127.0.0.1:5000",
                        RemoteEndpoint = "127.0.0.1:5001",
                        State = "Established",
                        Direction = ConnectionDirection.Outbound,
                        InterfaceName = string.Empty,
                        FirstObservedUtc = DateTimeOffset.UtcNow,
                        Quality = DataQuality.Observed,
                    },
                ],
            };

            var health = new ServiceHealth
            {
                Status = "running",
                UptimeSeconds = 5,
                SourceName = "test-source",
                PollIntervalSeconds = 1,
                ConnectionCount = snapshot.Connections.Count,
                ProcessCount = snapshot.ProcessCount,
            };

            var server = new PipeServer(
                pipeName,
                sid,
                () => snapshot,
                () => health,
                historyQuery: null,
                rulesQuery: firewall is null ? null : _ => Task.FromResult(firewall),
                networkRecoveryCapture: networkRecoveryCapture,
                networkRecoveryRestore: networkRecoveryRestore);

            var host = new ServerHost(pipeName, server);
            await host.WaitUntilReadyAsync();
            return host;
        }

        public async ValueTask DisposeAsync()
        {
            await _cancellation.CancelAsync();
            _cancellation.Dispose();

            try
            {
                await _run.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (TimeoutException)
            {
                // The accept loop is blocked in WaitForConnectionAsync without a cancellation token.
            }
        }

        private async Task WaitUntilReadyAsync()
        {
            for (var attempt = 0; attempt < 60; attempt++)
            {
                if (Directory.GetFiles(@"\\.\pipe\").Any(path =>
                        string.Equals(Path.GetFileName(path), PipeName, StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }

                await Task.Delay(50);
            }

            throw new InvalidOperationException($"Pipe '{PipeName}' was not created in time.");
        }
    }
}
