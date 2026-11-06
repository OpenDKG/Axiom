// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Privacy;

namespace Axiom.Contracts.Ipc;

/// <summary>
/// Transport-neutral request dispatcher. Both the Windows named pipe server and the Unix domain
/// socket server call this type, so the command surface, write gate and error contract cannot
/// drift between platforms. There is no generic exec path.
/// </summary>
public sealed class IpcRequestProcessor
{
    private readonly Func<ConnectionSnapshot?> _snapshot;
    private readonly Func<ServiceHealth> _health;
    private readonly Func<HistoryQuery, CancellationToken, Task<HistoryPage>>? _historyQuery;
    private readonly Func<CancellationToken, Task<FirewallRulesSnapshot>>? _rulesQuery;
    private readonly Func<RuleSpec, string, CancellationToken, Task<RuleApplyResult>>? _ruleApply;
    private readonly Func<Guid, string, CancellationToken, Task<RuleApplyResult>>? _ruleRemove;
    private readonly Func<Guid, CancellationToken, Task<EffectiveRuleReport>>? _ruleVerify;
    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacyStatus;
    private readonly Func<PrivacyShieldSettings, CancellationToken, Task<PrivacyShieldStatus>>? _privacyConfigure;
    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacySourcesUpdate;
    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacyHistoryClear;
    private readonly Func<bool> _firewallWritesEnabled;
    private readonly Action<string>? _log;

    public IpcRequestProcessor(
        Func<ConnectionSnapshot?> snapshot,
        Func<ServiceHealth> health,
        Func<HistoryQuery, CancellationToken, Task<HistoryPage>>? historyQuery = null,
        Func<CancellationToken, Task<FirewallRulesSnapshot>>? rulesQuery = null,
        Func<RuleSpec, string, CancellationToken, Task<RuleApplyResult>>? ruleApply = null,
        Func<Guid, string, CancellationToken, Task<RuleApplyResult>>? ruleRemove = null,
        Func<Guid, CancellationToken, Task<EffectiveRuleReport>>? ruleVerify = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacyStatus = null,
        Func<PrivacyShieldSettings, CancellationToken, Task<PrivacyShieldStatus>>? privacyConfigure = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacySourcesUpdate = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacyHistoryClear = null,
        Func<bool>? firewallWritesEnabled = null,
        Action<string>? log = null)
    {
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        _health = health ?? throw new ArgumentNullException(nameof(health));
        _historyQuery = historyQuery;
        _rulesQuery = rulesQuery;
        _ruleApply = ruleApply;
        _ruleRemove = ruleRemove;
        _ruleVerify = ruleVerify;
        _privacyStatus = privacyStatus;
        _privacyConfigure = privacyConfigure;
        _privacySourcesUpdate = privacySourcesUpdate;
        _privacyHistoryClear = privacyHistoryClear;
        _firewallWritesEnabled = firewallWritesEnabled ?? (() => false);
        _log = log;
    }

    /// <summary>Processes one NDJSON line. Returns false when the connection must be closed.</summary>
    public async Task<bool> ProcessAsync(
        Stream stream,
        string line,
        string actorId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        IpcEnvelope? envelope;

        try
        {
            envelope = JsonSerializer.Deserialize<IpcEnvelope>(line, IpcJson.Options);
        }
        catch (JsonException)
        {
            await WriteErrorAsync(stream, Guid.Empty, IpcErrorCodes.InvalidRequest, "Malformed JSON envelope.", cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        if (envelope is null)
        {
            await WriteErrorAsync(stream, Guid.Empty, IpcErrorCodes.InvalidRequest, "Empty envelope.", cancellationToken)
                .ConfigureAwait(false);
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
                    await WriteResultAsync(stream, envelope.Id, _health(), cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.Capabilities:
                    await WriteResultAsync(stream, envelope.Id, CreateCapabilities(), cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.Snapshot:
                    var snapshot = _snapshot();
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
                    if (_ruleApply is null || !_firewallWritesEnabled())
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

                    var applied = await _ruleApply(spec, actorId, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, applied, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.RuleRemove:
                    if (_ruleRemove is null || !_firewallWritesEnabled())
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

                    var removed = await _ruleRemove(removeReference.ManagedRuleId, actorId, cancellationToken).ConfigureAwait(false);
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

                    var privacyResult = await _privacyConfigure(privacySettings, cancellationToken).ConfigureAwait(false);
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

                case IpcCommandTypes.PrivacyHistoryClear:
                    if (_privacyHistoryClear is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Privacy Shield history is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var historyResult = await _privacyHistoryClear(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, historyResult, cancellationToken).ConfigureAwait(false);
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

    public ServiceCapabilities CreateCapabilities()
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

        if (_privacyHistoryClear is not null)
        {
            commands.Add(IpcCommandTypes.PrivacyHistoryClear);
        }

        var writesEnabled = _firewallWritesEnabled();
        if (writesEnabled)
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
            FirewallWrites = writesEnabled,
            Milestone = ProductMilestone.Current,
        };
    }

    public static async Task WriteResultAsync<T>(
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

        var json = JsonSerializer.Serialize(response, IpcJson.Options);
        if (Encoding.UTF8.GetByteCount(json) > IpcProtocol.MaxResponseBytes)
        {
            await WriteErrorAsync(
                stream,
                requestId,
                IpcErrorCodes.InvalidRequest,
                $"Response exceeded {IpcProtocol.MaxResponseBytes} bytes; narrow the request.",
                cancellationToken).ConfigureAwait(false);
            return;
        }

        await IpcLineProtocol
            .WriteLineAsync(stream, json, cancellationToken)
            .ConfigureAwait(false);
    }

    public static async Task WriteErrorAsync(
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
}

/// <summary>
/// Per-connection loop shared by both transports: idle timeout, byte cap, rate limit and ordered
/// single-request processing. Keep the limits identical on every platform.
/// </summary>
public static class IpcConnectionHandler
{
    public const int MaxRequestsPerSecond = 100;

    public static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(30);

    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    /// <summary>A response that cannot be written must not pin the handler; every error path gets its own deadline.</summary>
    public static readonly TimeSpan ResponseWriteTimeout = TimeSpan.FromSeconds(10);

    public static Task ServeAsync(
        Stream stream,
        string actorId,
        IpcRequestProcessor processor,
        Action<string>? log,
        CancellationToken cancellationToken) =>
        ServeAsync(stream, actorId, processor, log, null, cancellationToken);

    public static async Task ServeAsync(
        Stream stream,
        string actorId,
        IpcRequestProcessor processor,
        Action<string>? log,
        TimeSpan? responseWriteTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(processor);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorId);

        using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        idle.CancelAfter(IdleTimeout);

        var reader = new IpcLineReader(stream);
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
                // A stalled reader must not inherit the idle deadline: use a dedicated write
                // deadline so the oversized-request error is bounded and the handler exits.
                await WriteBoundedAsync(
                    token => IpcRequestProcessor.WriteErrorAsync(
                        stream,
                        Guid.Empty,
                        IpcErrorCodes.MessageTooLarge,
                        $"Message exceeded {IpcProtocol.MaxMessageBytes} bytes.",
                        token),
                    responseWriteTimeout ?? ResponseWriteTimeout,
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

            // A client that stops reading must not pin a handler forever. Bound processing and
            // every response/error write, not only the next read.
            using var request = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                idle.Token);
            request.CancelAfter(RequestTimeout);

            var now = DateTime.UtcNow;
            if (now - windowStart >= TimeSpan.FromSeconds(1))
            {
                requestsInWindow = 0;
                windowStart = now;
            }

            requestsInWindow++;
            if (requestsInWindow > MaxRequestsPerSecond)
            {
                await WriteBoundedAsync(
                    token => IpcRequestProcessor.WriteErrorAsync(
                        stream,
                        Guid.Empty,
                        IpcErrorCodes.InvalidRequest,
                        "Rate limit exceeded.",
                        token),
                    responseWriteTimeout ?? ResponseWriteTimeout,
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!await processor.ProcessAsync(stream, line, actorId, request.Token).ConfigureAwait(false))
            {
                return;
            }

            // Slide the idle window: activity keeps the connection alive, silence ends it.
            idle.CancelAfter(IdleTimeout);

        }
    }

    private static async Task WriteBoundedAsync(
        Func<CancellationToken, Task> write,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);

        try
        {
            await write(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The peer stopped reading; the handler must still terminate.
        }
    }
}
