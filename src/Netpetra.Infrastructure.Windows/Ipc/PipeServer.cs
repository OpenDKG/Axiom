// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Text.Json;
using Netpetra.Contracts;
using Netpetra.Contracts.Firewall;
using Netpetra.Contracts.History;
using Netpetra.Contracts.Ipc;
using Netpetra.Contracts.Monitoring;
using Netpetra.Contracts.Privacy;
using Netpetra.Infrastructure.Windows.Firewall;

namespace Netpetra.Infrastructure.Windows.Ipc;

/// <summary>
/// Local-only Named Pipe server. The DACL is explicit, the client SID is verified after connect,
/// messages are bounded and only named commands are dispatched. There is no generic exec path.
/// </summary>
public sealed class PipeServer
{
    private const int MaxInstances = 4;

    private const int BufferSize = 64 * 1024;

    private const int MaxRequestsPerSecond = 100;

    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(30);

    private readonly string _pipeName;

    private readonly string _allowedSid;

    private readonly Func<ConnectionSnapshot?> _snapshotProvider;

    private readonly Func<ServiceHealth> _healthProvider;

    private readonly Func<HistoryQuery, CancellationToken, Task<HistoryPage>>? _historyQuery;

    private readonly Func<CancellationToken, Task<FirewallRulesSnapshot>>? _rulesQuery;

    private readonly Func<RuleSpec, string, CancellationToken, Task<RuleApplyResult>>? _ruleApply;

    private readonly Func<Guid, string, CancellationToken, Task<RuleApplyResult>>? _ruleRemove;

    private readonly Func<Guid, CancellationToken, Task<EffectiveRuleReport>>? _ruleVerify;

    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacyStatus;

    private readonly Func<PrivacyShieldSettings, CancellationToken, Task<PrivacyShieldStatus>>? _privacyConfigure;

    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacySourcesUpdate;

    private readonly Action<string>? _log;

    public PipeServer(
        string pipeName,
        string allowedSid,
        Func<ConnectionSnapshot?> snapshotProvider,
        Func<ServiceHealth> healthProvider,
        Func<HistoryQuery, CancellationToken, Task<HistoryPage>>? historyQuery = null,
        Func<CancellationToken, Task<FirewallRulesSnapshot>>? rulesQuery = null,
        Func<RuleSpec, string, CancellationToken, Task<RuleApplyResult>>? ruleApply = null,
        Func<Guid, string, CancellationToken, Task<RuleApplyResult>>? ruleRemove = null,
        Func<Guid, CancellationToken, Task<EffectiveRuleReport>>? ruleVerify = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacyStatus = null,
        Func<PrivacyShieldSettings, CancellationToken, Task<PrivacyShieldStatus>>? privacyConfigure = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacySourcesUpdate = null,
        Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentException.ThrowIfNullOrWhiteSpace(allowedSid);

        _pipeName = pipeName;
        _allowedSid = allowedSid;
        _snapshotProvider = snapshotProvider ?? throw new ArgumentNullException(nameof(snapshotProvider));
        _healthProvider = healthProvider ?? throw new ArgumentNullException(nameof(healthProvider));
        _historyQuery = historyQuery;
        _rulesQuery = rulesQuery;
        _ruleApply = ruleApply;
        _ruleRemove = ruleRemove;
        _ruleVerify = ruleVerify;
        _privacyStatus = privacyStatus;
        _privacyConfigure = privacyConfigure;
        _privacySourcesUpdate = privacySourcesUpdate;
        _log = log;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream server;

            try
            {
                server = CreateServer();
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                _log?.Invoke($"Pipe server could not start: {exception.Message}");
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                continue;
            }

            try
            {
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await server.DisposeAsync().ConfigureAwait(false);
                break;
            }
            catch (IOException exception)
            {
                _log?.Invoke($"Pipe connection failed: {exception.Message}");
                await server.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            // Ownership moves to the handler; the accept loop immediately creates the next instance.
            _ = HandleClientAsync(server, cancellationToken);
        }
    }

    private NamedPipeServerStream CreateServer() =>
        NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            MaxInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            BufferSize,
            BufferSize,
            PipeSecurityFactory.Create(_allowedSid));

    private async Task HandleClientAsync(NamedPipeServerStream server, CancellationToken cancellationToken)
    {
        await using (server.ConfigureAwait(false))
        {
            var clientSid = PipeClientIdentity.TryGetClientSid(server.SafePipeHandle);
            if (!string.Equals(clientSid, _allowedSid, StringComparison.OrdinalIgnoreCase))
            {
                _log?.Invoke($"Rejected pipe client with SID '{clientSid ?? "unknown"}'.");
                return;
            }

            using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            idle.CancelAfter(IdleTimeout);

            var reader = new IpcLineReader(server);
            var requestsInWindow = 0;
            var windowStart = DateTime.UtcNow;

            while (!cancellationToken.IsCancellationRequested)
            {
                string? line;

                try
                {
                    line = await reader
                        .ReadLineAsync(IpcProtocol.MaxMessageBytes, idle.Token)
                        .ConfigureAwait(false);
                }
                catch (IpcMessageTooLargeException)
                {
                    await WriteErrorAsync(
                        server,
                        Guid.Empty,
                        IpcErrorCodes.MessageTooLarge,
                        $"Message exceeded {IpcProtocol.MaxMessageBytes} bytes.",
                        cancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (IOException)
                {
                    return;
                }

                if (line is null)
                {
                    return;
                }

                if (!await ProcessAsync(server, line, clientSid!, cancellationToken).ConfigureAwait(false))
                {
                    return;
                }

                requestsInWindow++;
                if (DateTime.UtcNow - windowStart >= TimeSpan.FromSeconds(1))
                {
                    requestsInWindow = 0;
                    windowStart = DateTime.UtcNow;
                }
                else if (requestsInWindow > MaxRequestsPerSecond)
                {
                    await WriteErrorAsync(
                        server,
                        Guid.Empty,
                        IpcErrorCodes.InvalidRequest,
                        "Rate limit exceeded.",
                        cancellationToken).ConfigureAwait(false);
                    return;
                }
            }
        }
    }

    private async Task<bool> ProcessAsync(
        Stream stream,
        string line,
        string actorSid,
        CancellationToken cancellationToken)
    {
        IpcEnvelope? envelope;

        try
        {
            envelope = JsonSerializer.Deserialize<IpcEnvelope>(line, IpcJson.Options);
        }
        catch (JsonException)
        {
            await WriteErrorAsync(
                stream,
                Guid.Empty,
                IpcErrorCodes.InvalidRequest,
                "Malformed JSON envelope.",
                cancellationToken).ConfigureAwait(false);
            return false;
        }

        if (envelope is null)
        {
            await WriteErrorAsync(
                stream,
                Guid.Empty,
                IpcErrorCodes.InvalidRequest,
                "Empty envelope.",
                cancellationToken).ConfigureAwait(false);
            return false;
        }

        if (!IpcProtocol.IsSupported(envelope.Version))
        {
            await WriteErrorAsync(
                stream,
                envelope.Id,
                IpcErrorCodes.InvalidRequest,
                $"Unsupported protocol version {envelope.Version}.",
                cancellationToken).ConfigureAwait(false);
            return true;
        }

        try
        {
            switch (envelope.Type)
            {
                case IpcCommandTypes.ServiceHealth:
                    await WriteResultAsync(stream, envelope.Id, _healthProvider(), cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.Capabilities:
                    await WriteResultAsync(stream, envelope.Id, CreateCapabilities(), cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.Snapshot:
                    var snapshot = _snapshotProvider();
                    if (snapshot is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.ServiceUnavailable,
                            "The monitoring worker has not produced a snapshot yet.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    await WriteResultAsync(stream, envelope.Id, snapshot, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.HistoryQuery:
                    if (_historyQuery is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "History is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    if (envelope.Payload is not { } payload)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "History query payload is required.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    HistoryQuery? query;
                    try
                    {
                        query = payload.Deserialize<HistoryQuery>(IpcJson.Options);
                    }
                    catch (JsonException)
                    {
                        query = null;
                    }

                    if (query is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "History query payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var page = await _historyQuery(query, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, page, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.RulesQuery:
                    if (_rulesQuery is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Firewall rule query is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var firewall = await _rulesQuery(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, firewall, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.RuleApply:
                    if (_ruleApply is null || !WindowsFirewallPolicyAdapter.IsWriteGateOpen)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Firewall writes are disabled on this service.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var spec = DeserializePayload<RuleSpec>(envelope.Payload);
                    if (spec is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Rule apply payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var applied = await _ruleApply(spec, actorSid, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, applied, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.RuleRemove:
                    if (_ruleRemove is null || !WindowsFirewallPolicyAdapter.IsWriteGateOpen)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Firewall writes are disabled on this service.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var removeReference = DeserializePayload<RuleReference>(envelope.Payload);
                    if (removeReference is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Rule remove payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var removed = await _ruleRemove(removeReference.ManagedRuleId, actorSid, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, removed, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.RuleVerify:
                    if (_ruleVerify is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Rule verification is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var verifyReference = DeserializePayload<RuleReference>(envelope.Payload);
                    if (verifyReference is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Rule verify payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var report = await _ruleVerify(verifyReference.ManagedRuleId, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, report, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.PrivacyStatus:
                    if (_privacyStatus is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Privacy Shield is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var privacyStatus = await _privacyStatus(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, privacyStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.PrivacyConfigure:
                    if (_privacyConfigure is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Privacy Shield configuration is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var privacySettings = DeserializePayload<PrivacyShieldSettings>(envelope.Payload);
                    if (privacySettings is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Privacy Shield settings payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var privacyResult = await _privacyConfigure(privacySettings, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, privacyResult, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.PrivacySourcesUpdate:
                    if (_privacySourcesUpdate is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Privacy Shield source updates are not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var sourceResult = await _privacySourcesUpdate(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, sourceResult, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ConfigGet:
                case IpcCommandTypes.ConfigSet:
                case IpcCommandTypes.DiagnosticsExport:
                case IpcCommandTypes.LiveEvents:
                    await WriteErrorAsync(
                        stream,
                        envelope.Id,
                        IpcErrorCodes.NotSupported,
                        $"Command '{envelope.Type}' is not implemented in {ProductMilestone.Current}.",
                        cancellationToken).ConfigureAwait(false);
                    break;

                default:
                    await WriteErrorAsync(
                        stream,
                        envelope.Id,
                        IpcErrorCodes.UnknownCommand,
                        $"Unknown command '{envelope.Type}'.",
                        cancellationToken).ConfigureAwait(false);
                    break;
            }

            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            await WriteErrorAsync(
                stream,
                envelope.Id,
                IpcErrorCodes.InternalError,
                "The service failed to process the request.",
                cancellationToken).ConfigureAwait(false);
            _log?.Invoke($"Request '{envelope.Type}' failed: {exception.Message}");
            return true;
        }
    }

    private ServiceCapabilities CreateCapabilities()
    {
        var commands = new List<string>
        {
            IpcCommandTypes.ServiceHealth,
            IpcCommandTypes.Capabilities,
            IpcCommandTypes.Snapshot,
        };

        if (_historyQuery is not null)
        {
            commands.Add(IpcCommandTypes.HistoryQuery);
        }

        if (_rulesQuery is not null)
        {
            commands.Add(IpcCommandTypes.RulesQuery);
        }

        if (_privacyStatus is not null)
        {
            commands.Add(IpcCommandTypes.PrivacyStatus);
        }

        if (_privacyConfigure is not null)
        {
            commands.Add(IpcCommandTypes.PrivacyConfigure);
        }

        if (_privacySourcesUpdate is not null)
        {
            commands.Add(IpcCommandTypes.PrivacySourcesUpdate);
        }

        if (WindowsFirewallPolicyAdapter.IsWriteGateOpen)
        {
            if (_ruleApply is not null)
            {
                commands.Add(IpcCommandTypes.RuleApply);
            }

            if (_ruleRemove is not null)
            {
                commands.Add(IpcCommandTypes.RuleRemove);
            }

            if (_ruleVerify is not null)
            {
                commands.Add(IpcCommandTypes.RuleVerify);
            }
        }

        return new ServiceCapabilities
        {
            ProtocolVersion = IpcProtocol.CurrentVersion,
            Commands = commands,
            Monitoring = true,
            FirewallWrites = WindowsFirewallPolicyAdapter.IsWriteGateOpen,
            Milestone = ProductMilestone.Current,
        };
    }

    private static T? DeserializePayload<T>(JsonElement? payload)
        where T : class
    {
        if (payload is not { } element)
        {
            return null;
        }

        try
        {
            return element.Deserialize<T>(IpcJson.Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static async Task WriteResultAsync<T>(
        Stream stream,
        Guid requestId,
        T result,
        CancellationToken cancellationToken)
    {
        var response = new IpcResponse
        {
            Id = requestId,
            Ok = true,
            Result = JsonSerializer.SerializeToElement(result, IpcJson.Options),
        };

        await IpcLineProtocol
            .WriteLineAsync(stream, JsonSerializer.Serialize(response, IpcJson.Options), cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task WriteErrorAsync(
        Stream stream,
        Guid requestId,
        string code,
        string message,
        CancellationToken cancellationToken)
    {
        var response = new IpcResponse
        {
            Id = requestId,
            Ok = false,
            Error = new IpcError(code, message),
        };

        await IpcLineProtocol
            .WriteLineAsync(stream, JsonSerializer.Serialize(response, IpcJson.Options), cancellationToken)
            .ConfigureAwait(false);
    }
}
