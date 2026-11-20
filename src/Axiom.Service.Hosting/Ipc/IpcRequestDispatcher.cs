// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Axiom.Contracts;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Protection;
using Axiom.Contracts.Threat;

namespace Axiom.Service.Hosting.Ipc;

/// <summary>
/// Transport-independent request loop of the local service endpoint. A platform transport (the
/// Windows named pipe with DACL + SID check, the macOS Unix socket with peer-uid check) accepts and
/// authenticates a client, then hands the stream and the caller identity to
/// <see cref="HandleConnectionAsync"/>. Messages are bounded and only named commands are
/// dispatched. There is no generic exec path.
/// </summary>
public sealed class IpcRequestDispatcher
{
    public const int MaxRequestsPerSecond = 100;

    public static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(30);

    private readonly Func<ConnectionSnapshot?> _snapshotProvider;

    private readonly Func<ServiceHealth> _healthProvider;

    private readonly Func<HistoryQuery, CancellationToken, Task<HistoryPage>>? _historyQuery;

    private readonly Func<ThroughputHistoryQuery, CancellationToken, Task<ThroughputHistory>>? _throughputHistory;

    private readonly Func<CancellationToken, Task<FirewallRulesSnapshot>>? _rulesQuery;

    private readonly Func<RuleSpec, string, CancellationToken, Task<RuleApplyResult>>? _ruleApply;

    private readonly Func<Guid, string, CancellationToken, Task<RuleApplyResult>>? _ruleRemove;

    private readonly Func<Guid, CancellationToken, Task<EffectiveRuleReport>>? _ruleVerify;

    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacyStatus;

    private readonly Func<PrivacyShieldSettings, CancellationToken, Task<PrivacyShieldStatus>>? _privacyConfigure;

    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacySourcesUpdate;

    private readonly Func<CancellationToken, Task<PrivacyShieldStatus>>? _privacyHistoryClear;

    private readonly Func<CancellationToken, Task<ProtectionStatus>>? _protectionStatus;

    private readonly Func<ProtectionEnableRequest, string, CancellationToken, Task<ProtectionStatus>>? _protectionEnable;

    private readonly Func<string, CancellationToken, Task<ProtectionStatus>>? _protectionDisable;

    private readonly Func<ProtectionDecideRequest, string, CancellationToken, Task<ProtectionStatus>>? _protectionDecide;

    private readonly Func<ProtectionDismissRequest, CancellationToken, Task<ProtectionStatus>>? _protectionDismiss;

    private readonly Func<ProtectionLockdownRequest, string, CancellationToken, Task<ProtectionStatus>>? _protectionLockdown;

    private readonly Func<CancellationToken, Task<ThreatShareQueueStatus>>? _threatShareStatus;

    private readonly Func<ThreatShareEnqueueRequest, CancellationToken, Task<ThreatShareQueueStatus>>? _threatShareEnqueue;

    private readonly Func<ThreatShareVerifyRequest, CancellationToken, Task<ThreatShareQueueStatus>>? _threatShareVerify;

    private readonly Func<ThreatShareDismissRequest, CancellationToken, Task<ThreatShareQueueStatus>>? _threatShareDismiss;

    private readonly Func<ThreatShareRecordRequest, CancellationToken, Task<ThreatShareQueueStatus>>? _threatShareRecord;

    private readonly Func<string, CancellationToken, Task<NetworkRecoveryCaptureResult>>? _networkRecoveryCapture;

    private readonly Func<string, CancellationToken, Task<NetworkRecoveryRestoreResult>>? _networkRecoveryRestore;

    private readonly Func<CancellationToken, Task<EnforcementStatusDto>>? _enforcementStatus;

    private readonly Func<EnforcementEvaluateRequest, string, CancellationToken, Task<EnforcementVerdictDto>>? _enforcementEvaluate;

    private readonly Func<CancellationToken, Task<EnforcementReceiptsSnapshotDto>>? _enforcementReceipts;

    private readonly Func<bool> _writeGateOpen;

    private readonly Action<string>? _log;

    /// <param name="handlers">Command handlers.</param>
    /// <param name="writeGateOpen">Firewall write gate; defaults to <see cref="Axiom.Core.Firewall.FirewallWriteGate.IsOpen"/>.</param>
    /// <param name="log">Optional diagnostic sink.</param>
    public IpcRequestDispatcher(
        IpcRequestHandlers handlers,
        Func<bool>? writeGateOpen = null,
        Action<string>? log = null)
    {
        ArgumentNullException.ThrowIfNull(handlers);

        _snapshotProvider = handlers.SnapshotProvider ?? throw new ArgumentException("SnapshotProvider is required.", nameof(handlers));
        _healthProvider = handlers.HealthProvider ?? throw new ArgumentException("HealthProvider is required.", nameof(handlers));
        _historyQuery = handlers.HistoryQuery;
        _throughputHistory = handlers.ThroughputHistory;
        _rulesQuery = handlers.RulesQuery;
        _ruleApply = handlers.RuleApply;
        _ruleRemove = handlers.RuleRemove;
        _ruleVerify = handlers.RuleVerify;
        _privacyStatus = handlers.PrivacyStatus;
        _privacyConfigure = handlers.PrivacyConfigure;
        _privacySourcesUpdate = handlers.PrivacySourcesUpdate;
        _privacyHistoryClear = handlers.PrivacyHistoryClear;
        _protectionStatus = handlers.ProtectionStatus;
        _protectionEnable = handlers.ProtectionEnable;
        _protectionDisable = handlers.ProtectionDisable;
        _protectionDecide = handlers.ProtectionDecide;
        _protectionDismiss = handlers.ProtectionDismiss;
        _protectionLockdown = handlers.ProtectionLockdown;
        _threatShareStatus = handlers.ThreatShareStatus;
        _threatShareEnqueue = handlers.ThreatShareEnqueue;
        _threatShareVerify = handlers.ThreatShareVerify;
        _threatShareDismiss = handlers.ThreatShareDismiss;
        _threatShareRecord = handlers.ThreatShareRecord;
        _networkRecoveryCapture = handlers.NetworkRecoveryCapture;
        _networkRecoveryRestore = handlers.NetworkRecoveryRestore;
        _enforcementStatus = handlers.EnforcementStatus;
        _enforcementEvaluate = handlers.EnforcementEvaluate;
        _enforcementReceipts = handlers.EnforcementReceipts;
        _writeGateOpen = writeGateOpen ?? (() => Axiom.Core.Firewall.FirewallWriteGate.IsOpen);
        _log = log;
    }

    /// <summary>
    /// Serves one authenticated connection until the client closes it, idles out, exceeds the
    /// message bound or the rate limit, or <paramref name="cancellationToken"/> fires.
    /// The transport must say who the caller is and what it may do: there is deliberately no
    /// overload that takes a bare actor string. Commands outside the caller's classes
    /// (<see cref="IpcCaller.Permits"/>) are refused with <see cref="IpcErrorCodes.Unauthorized"/>.
    /// </summary>
    public async Task HandleConnectionAsync(Stream stream, IpcCaller caller, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentException.ThrowIfNullOrWhiteSpace(caller.Actor);

        using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var reader = new IpcLineReader(stream);
        var requestsInWindow = 0;
        var windowStart = DateTime.UtcNow;

        while (!cancellationToken.IsCancellationRequested)
        {
            idle.CancelAfter(IdleTimeout);
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
                    stream,
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

            var now = DateTime.UtcNow;
            if (now - windowStart >= TimeSpan.FromSeconds(1))
            {
                requestsInWindow = 0;
                windowStart = now;
            }

            requestsInWindow++;
            if (requestsInWindow > MaxRequestsPerSecond)
            {
                await WriteErrorAsync(
                    stream,
                    Guid.Empty,
                    IpcErrorCodes.InvalidRequest,
                    "Rate limit exceeded.",
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!await ProcessAsync(stream, line, caller, cancellationToken).ConfigureAwait(false))
            {
                return;
            }
        }
    }

    private async Task<bool> ProcessAsync(
        Stream stream,
        string line,
        IpcCaller caller,
        CancellationToken cancellationToken)
    {
        var actorSid = caller.Actor;
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

        var commandClass = IpcCommandAccess.Classify(envelope.Type);
        if (!caller.Permits(commandClass))
        {
            var kind = commandClass == IpcCommandClass.PrivateRead ? "private read" : "write";
            _log?.Invoke($"Denied '{envelope.Type}' for {actorSid}: {kind} commands are not allowed for this caller.");
            await WriteErrorAsync(
                stream,
                envelope.Id,
                IpcErrorCodes.Unauthorized,
                caller.DenialMessage(commandClass, envelope.Type),
                cancellationToken).ConfigureAwait(false);
            return true;
        }

        try
        {
            switch (envelope.Type)
            {
                case IpcCommandTypes.ServiceHealth:
                    var health = _healthProvider();
                    await WriteResultAsync(
                        stream,
                        envelope.Id,
                        caller.CanReadPrivate ? health : IpcCommandAccess.RedactHealth(health),
                        cancellationToken).ConfigureAwait(false);
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

                case IpcCommandTypes.ThroughputHistory:
                    if (_throughputHistory is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Throughput history is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var throughputQuery = DeserializePayload<ThroughputHistoryQuery>(envelope.Payload);
                    if (throughputQuery is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Throughput history payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var throughput = await _throughputHistory(throughputQuery, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, throughput, cancellationToken)
                        .ConfigureAwait(false);
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
                    if (_ruleApply is null || !_writeGateOpen())
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

                    // A same-user process can reach this pipe. Inbound allow is the one rule shape
                    // that opens a listening port to the network, so it is not accepted here even
                    // for the allowed SID; the interactive UI cannot request it either.
                    if (IpcRulePolicy.IsRejected(spec))
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Inbound allow rules are not accepted over the local pipe.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var applied = await _ruleApply(spec, actorSid, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, applied, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.RuleRemove:
                    if (_ruleRemove is null || !_writeGateOpen())
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

                case IpcCommandTypes.ProtectionStatus:
                    if (_protectionStatus is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Axiom Shield is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var protectionStatus = await _protectionStatus(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, protectionStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ProtectionEnable:
                    if (_protectionEnable is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Axiom Shield is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var enableRequest = DeserializePayload<ProtectionEnableRequest>(envelope.Payload)
                                        ?? new ProtectionEnableRequest();
                    var enabledStatus = await _protectionEnable(enableRequest, actorSid, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, enabledStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ProtectionDisable:
                    if (_protectionDisable is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Axiom Shield is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var disabledStatus = await _protectionDisable(actorSid, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, disabledStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ProtectionDecide:
                    if (_protectionDecide is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Axiom Shield is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var decideRequest = DeserializePayload<ProtectionDecideRequest>(envelope.Payload);
                    if (decideRequest is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Decision payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var decidedStatus = await _protectionDecide(decideRequest, actorSid, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, decidedStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ProtectionDismiss:
                    if (_protectionDismiss is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Axiom Shield is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var dismissRequest = DeserializePayload<ProtectionDismissRequest>(envelope.Payload);
                    if (dismissRequest is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Dismiss payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var dismissedStatus = await _protectionDismiss(dismissRequest, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, dismissedStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ProtectionLockdown:
                    if (_protectionLockdown is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Axiom Shield is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var lockdownRequest = DeserializePayload<ProtectionLockdownRequest>(envelope.Payload)
                                          ?? new ProtectionLockdownRequest();
                    var lockdownStatus = await _protectionLockdown(lockdownRequest, actorSid, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, lockdownStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ThreatShareStatus:
                    if (_threatShareStatus is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Threat sharing is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var shareStatus = await _threatShareStatus(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, shareStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ThreatShareEnqueue:
                    if (_threatShareEnqueue is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Threat sharing is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var enqueueRequest = DeserializePayload<ThreatShareEnqueueRequest>(envelope.Payload);
                    if (enqueueRequest is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Threat share payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var enqueued = await _threatShareEnqueue(enqueueRequest, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, enqueued, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ThreatShareVerify:
                    if (_threatShareVerify is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Threat sharing is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var verifyRequest = DeserializePayload<ThreatShareVerifyRequest>(envelope.Payload);
                    if (verifyRequest is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Threat share verify payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var verified = await _threatShareVerify(verifyRequest, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, verified, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ThreatShareDismiss:
                    if (_threatShareDismiss is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Threat sharing is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var dismissShare = DeserializePayload<ThreatShareDismissRequest>(envelope.Payload);
                    if (dismissShare is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Threat share dismiss payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var dismissed = await _threatShareDismiss(dismissShare, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, dismissed, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.ThreatShareRecord:
                    if (_threatShareRecord is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Threat sharing is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var recordRequest = DeserializePayload<ThreatShareRecordRequest>(envelope.Payload);
                    if (recordRequest is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Threat share record payload is invalid.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var recorded = await _threatShareRecord(recordRequest, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, recorded, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.NetworkRecoveryCapture:
                    if (_networkRecoveryCapture is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Network recovery is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    // The request never carries adapter ids, DNS servers or rule names. The service
                    // captures machine state itself and the snapshot store validates it.
                    if (envelope.Payload is not null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Network recovery capture does not accept client-supplied state.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var captured = await _networkRecoveryCapture(actorSid, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, captured, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.NetworkRecoveryRestore:
                    if (_networkRecoveryRestore is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Network recovery is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    // Restore is limited to the validated machine snapshot; arbitrary DNS servers
                    // or rule names are never accepted over the pipe.
                    if (envelope.Payload is not null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "Network recovery restore does not accept client-supplied state.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var restored = await _networkRecoveryRestore(actorSid, cancellationToken)
                        .ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, restored, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.EnforcementStatus:
                    if (_enforcementStatus is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Agent enforcement is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var enforcementStatus = await _enforcementStatus(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, enforcementStatus, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.EnforcementEvaluate:
                    if (_enforcementEvaluate is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Agent enforcement is not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var enforcementRequest = DeserializePayload<EnforcementEvaluateRequest>(envelope.Payload);
                    if (enforcementRequest is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.InvalidRequest,
                            "An enforcement evaluate payload is required.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var enforcementVerdict = await _enforcementEvaluate(
                        enforcementRequest, actorSid, cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, enforcementVerdict, cancellationToken).ConfigureAwait(false);
                    break;

                case IpcCommandTypes.EnforcementReceipts:
                    if (_enforcementReceipts is null)
                    {
                        await WriteErrorAsync(
                            stream,
                            envelope.Id,
                            IpcErrorCodes.NotSupported,
                            "Agent enforcement receipts are not available in this build.",
                            cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var receipts = await _enforcementReceipts(cancellationToken).ConfigureAwait(false);
                    await WriteResultAsync(stream, envelope.Id, receipts, cancellationToken).ConfigureAwait(false);
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

        if (_throughputHistory is not null)
        {
            commands.Add(IpcCommandTypes.ThroughputHistory);
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

        if (_protectionStatus is not null)
        {
            commands.Add(IpcCommandTypes.ProtectionStatus);
        }

        if (_protectionEnable is not null)
        {
            commands.Add(IpcCommandTypes.ProtectionEnable);
        }

        if (_protectionDisable is not null)
        {
            commands.Add(IpcCommandTypes.ProtectionDisable);
        }

        if (_protectionDecide is not null)
        {
            commands.Add(IpcCommandTypes.ProtectionDecide);
        }

        if (_protectionDismiss is not null)
        {
            commands.Add(IpcCommandTypes.ProtectionDismiss);
        }

        if (_protectionLockdown is not null)
        {
            commands.Add(IpcCommandTypes.ProtectionLockdown);
        }

        if (_threatShareStatus is not null)
        {
            commands.Add(IpcCommandTypes.ThreatShareStatus);
        }

        if (_threatShareEnqueue is not null)
        {
            commands.Add(IpcCommandTypes.ThreatShareEnqueue);
        }

        if (_threatShareVerify is not null)
        {
            commands.Add(IpcCommandTypes.ThreatShareVerify);
        }

        if (_threatShareDismiss is not null)
        {
            commands.Add(IpcCommandTypes.ThreatShareDismiss);
        }

        if (_threatShareRecord is not null)
        {
            commands.Add(IpcCommandTypes.ThreatShareRecord);
        }

        if (_networkRecoveryCapture is not null)
        {
            commands.Add(IpcCommandTypes.NetworkRecoveryCapture);
        }

        if (_networkRecoveryRestore is not null)
        {
            commands.Add(IpcCommandTypes.NetworkRecoveryRestore);
        }

        if (_enforcementStatus is not null)
        {
            commands.Add(IpcCommandTypes.EnforcementStatus);
        }

        if (_enforcementEvaluate is not null)
        {
            commands.Add(IpcCommandTypes.EnforcementEvaluate);
        }

        if (_enforcementReceipts is not null)
        {
            commands.Add(IpcCommandTypes.EnforcementReceipts);
        }

        if (_writeGateOpen())
        {
            if (_ruleApply is not null)
            {
                commands.Add(IpcCommandTypes.RuleApply);
            }

            if (_ruleRemove is not null)
            {
                commands.Add(IpcCommandTypes.RuleRemove);
            }
        }

        // rule.verify is read-only and dispatched without the write gate, so advertise it whenever
        // the service can serve it. It stays a private read in IpcCommandAccess: the report names
        // rule and application paths, so the per-connection read check still applies.
        if (_ruleVerify is not null)
        {
            commands.Add(IpcCommandTypes.RuleVerify);
        }

        return new ServiceCapabilities
        {
            ProtocolVersion = IpcProtocol.CurrentVersion,
            Commands = commands,
            Monitoring = true,
            FirewallWrites = _writeGateOpen(),
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
