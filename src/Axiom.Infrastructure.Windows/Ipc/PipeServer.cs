// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Privacy;
using Axiom.Contracts.Protection;
using Axiom.Contracts.Threat;
using Axiom.Core.Firewall;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Windows.Ipc;

/// <summary>
/// Local-only Named Pipe server. The DACL is explicit, the client SID is verified after connect,
/// messages are bounded and only named commands are dispatched. There is no generic exec path.
/// The request loop itself is the portable <see cref="IpcRequestDispatcher"/>.
/// </summary>
public sealed class PipeServer
{
    private const int MaxInstances = 4;

    private const int BufferSize = 64 * 1024;

    private readonly string _pipeName;

    private readonly string _allowedSid;

    private readonly IpcRequestDispatcher _dispatcher;

    private readonly Action<string>? _log;

    public PipeServer(
        string pipeName,
        string allowedSid,
        Func<ConnectionSnapshot?> snapshotProvider,
        Func<ServiceHealth> healthProvider,
        Func<HistoryQuery, CancellationToken, Task<HistoryPage>>? historyQuery = null,
        Func<ThroughputHistoryQuery, CancellationToken, Task<ThroughputHistory>>? throughputHistory = null,
        Func<CancellationToken, Task<FirewallRulesSnapshot>>? rulesQuery = null,
        Func<RuleSpec, string, CancellationToken, Task<RuleApplyResult>>? ruleApply = null,
        Func<Guid, string, CancellationToken, Task<RuleApplyResult>>? ruleRemove = null,
        Func<Guid, CancellationToken, Task<EffectiveRuleReport>>? ruleVerify = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacyStatus = null,
        Func<PrivacyShieldSettings, CancellationToken, Task<PrivacyShieldStatus>>? privacyConfigure = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacySourcesUpdate = null,
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacyHistoryClear = null,
        Func<CancellationToken, Task<ProtectionStatus>>? protectionStatus = null,
        Func<ProtectionEnableRequest, string, CancellationToken, Task<ProtectionStatus>>? protectionEnable = null,
        Func<string, CancellationToken, Task<ProtectionStatus>>? protectionDisable = null,
        Func<ProtectionDecideRequest, string, CancellationToken, Task<ProtectionStatus>>? protectionDecide = null,
        Func<ProtectionDismissRequest, CancellationToken, Task<ProtectionStatus>>? protectionDismiss = null,
        Func<ProtectionLockdownRequest, string, CancellationToken, Task<ProtectionStatus>>? protectionLockdown = null,
        Func<CancellationToken, Task<ThreatShareQueueStatus>>? threatShareStatus = null,
        Func<ThreatShareEnqueueRequest, CancellationToken, Task<ThreatShareQueueStatus>>? threatShareEnqueue = null,
        Func<ThreatShareDismissRequest, CancellationToken, Task<ThreatShareQueueStatus>>? threatShareDismiss = null,
        Func<ThreatShareRecordRequest, CancellationToken, Task<ThreatShareQueueStatus>>? threatShareRecord = null,
        Action<string>? log = null)
        : this(
            pipeName,
            allowedSid,
            new IpcRequestHandlers
            {
                SnapshotProvider = snapshotProvider,
                HealthProvider = healthProvider,
                HistoryQuery = historyQuery,
                ThroughputHistory = throughputHistory,
                RulesQuery = rulesQuery,
                RuleApply = ruleApply,
                RuleRemove = ruleRemove,
                RuleVerify = ruleVerify,
                PrivacyStatus = privacyStatus,
                PrivacyConfigure = privacyConfigure,
                PrivacySourcesUpdate = privacySourcesUpdate,
                PrivacyHistoryClear = privacyHistoryClear,
                ProtectionStatus = protectionStatus,
                ProtectionEnable = protectionEnable,
                ProtectionDisable = protectionDisable,
                ProtectionDecide = protectionDecide,
                ProtectionDismiss = protectionDismiss,
                ProtectionLockdown = protectionLockdown,
                ThreatShareStatus = threatShareStatus,
                ThreatShareEnqueue = threatShareEnqueue,
                ThreatShareDismiss = threatShareDismiss,
                ThreatShareRecord = threatShareRecord,
            },
            log)
    {
    }

    public PipeServer(
        string pipeName,
        string allowedSid,
        IpcRequestHandlers handlers,
        Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentException.ThrowIfNullOrWhiteSpace(allowedSid);
        ArgumentNullException.ThrowIfNull(handlers);
        ArgumentNullException.ThrowIfNull(handlers.SnapshotProvider, nameof(handlers.SnapshotProvider));
        ArgumentNullException.ThrowIfNull(handlers.HealthProvider, nameof(handlers.HealthProvider));

        _pipeName = pipeName;
        _allowedSid = allowedSid;
        _log = log;
        _dispatcher = new IpcRequestDispatcher(handlers, () => FirewallWriteGate.IsOpen, log);
    }

    public PipeServer(
        string pipeName,
        string allowedSid,
        IpcRequestDispatcher dispatcher,
        Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentException.ThrowIfNullOrWhiteSpace(allowedSid);

        _pipeName = pipeName;
        _allowedSid = allowedSid;
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
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

            await _dispatcher.HandleConnectionAsync(server, clientSid!, cancellationToken).ConfigureAwait(false);
        }
    }
}
