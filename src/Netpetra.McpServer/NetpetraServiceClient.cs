// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.History;
using Netpetra.Contracts.Ipc;
using Netpetra.Contracts.Monitoring;

namespace Netpetra.McpServer;

public sealed class ServiceUnavailableException(string code, string message, Exception? inner = null)
    : Exception($"Axiom service unavailable: {message} ({code})", inner);

/// <summary>
/// Read-only client for the existing authenticated Netpetra Named Pipe. The MCP process never
/// touches SQLite or Windows Firewall COM objects directly.
/// </summary>
public sealed class NetpetraServiceClient(string pipeName = IpcPipe.Name)
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
