// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Privacy;
using Axiom.Infrastructure.Windows.Firewall;

namespace Axiom.Infrastructure.Windows.Ipc;

/// <summary>
/// Local-only Named Pipe server. The DACL is explicit, the client SID is verified after connect,
/// messages are bounded and only named commands are dispatched. There is no generic exec path.
/// </summary>
public sealed class PipeServer
{
    private const int MaxInstances = 4;

    private const int BufferSize = 64 * 1024;

    private readonly string _pipeName;

    private readonly string _allowedSid;

    private readonly IpcRequestProcessor _processor;

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
        Func<CancellationToken, Task<PrivacyShieldStatus>>? privacyHistoryClear = null,
        Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentException.ThrowIfNullOrWhiteSpace(allowedSid);

        _pipeName = pipeName;
        _allowedSid = allowedSid;
        _log = log;
        _processor = new IpcRequestProcessor(
            snapshotProvider ?? throw new ArgumentNullException(nameof(snapshotProvider)),
            healthProvider ?? throw new ArgumentNullException(nameof(healthProvider)),
            historyQuery,
            rulesQuery,
            ruleApply,
            ruleRemove,
            ruleVerify,
            privacyStatus,
            privacyConfigure,
            privacySourcesUpdate,
            privacyHistoryClear,
            () => WindowsFirewallPolicyAdapter.IsWriteGateOpen,
            log);
    }

    /// <summary>Processor-first overload used by the platform composition seam.</summary>
    public PipeServer(string pipeName, string allowedSid, IpcRequestProcessor processor, Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        ArgumentException.ThrowIfNullOrWhiteSpace(allowedSid);

        _pipeName = pipeName;
        _allowedSid = allowedSid;
        _processor = processor ?? throw new ArgumentNullException(nameof(processor));
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

            await IpcConnectionHandler
                .ServeAsync(server, clientSid!, _processor, _log, cancellationToken)
                .ConfigureAwait(false);
        }
    }
}
