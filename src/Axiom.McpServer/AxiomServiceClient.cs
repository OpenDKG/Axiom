// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;

namespace Axiom.McpServer;

public sealed class ServiceUnavailableException(string code, string message, Exception? inner = null)
    : Exception($"Axiom service unavailable: {message} ({code})", inner);

/// <summary>
/// Read-only client for the authenticated local service endpoint (named pipe on Windows, Unix
/// socket on Linux). The MCP process never touches SQLite or host firewall APIs directly.
/// </summary>
public sealed class AxiomServiceClient(string pipeName = IpcPipe.Name)
{
    private readonly IpcPipeClient _client = new(pipeName);

    public Task<ServiceHealth> GetHealthAsync(CancellationToken cancellationToken) =>
        SendAsync<ServiceHealth>(IpcCommandTypes.ServiceHealth, null, cancellationToken);

    public Task<ServiceCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken) =>
        SendAsync<ServiceCapabilities>(IpcCommandTypes.Capabilities, null, cancellationToken);

    public Task<ConnectionSnapshot> GetSnapshotAsync(CancellationToken cancellationToken) =>
        SendAsync<ConnectionSnapshot>(IpcCommandTypes.Snapshot, null, cancellationToken);

    public Task<HistoryPage> QueryHistoryAsync(HistoryQuery query, CancellationToken cancellationToken) =>
        SendAsync<HistoryPage>(IpcCommandTypes.HistoryQuery, query, cancellationToken);

    public Task<FirewallRulesSnapshot> GetFirewallRulesAsync(CancellationToken cancellationToken) =>
        SendAsync<FirewallRulesSnapshot>(IpcCommandTypes.RulesQuery, null, cancellationToken);

    private async Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
    {
        try
        {
            return await _client.SendAsync<T>(command, payload, cancellationToken).ConfigureAwait(false);
        }
        catch (IpcClientException exception)
        {
            throw new ServiceUnavailableException(exception.Code, exception.Message, exception);
        }
    }
}
