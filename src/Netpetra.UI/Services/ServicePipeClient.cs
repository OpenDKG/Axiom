// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Ipc;

namespace Netpetra.UI.Services;

public sealed class ServiceUnavailableException(string code, string message, Exception? inner = null)
    : Exception($"Service unavailable: {message} ({code})", inner);

/// <summary>
/// UI-facing adapter over the shared pipe client. It preserves the UI's existing exception contract
/// while the wire implementation lives in Contracts for reuse by the MCP process.
/// </summary>
public sealed class ServicePipeClient(string pipeName = IpcPipe.Name)
{
    private readonly IpcPipeClient _client = new(pipeName);

    public async Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
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
