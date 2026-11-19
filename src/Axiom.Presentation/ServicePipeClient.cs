// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;

namespace Axiom.Presentation;

/// <summary>
/// A typed service failure the UI can show without exposing transport details. The code and
/// message come from the local pipe protocol, which never carries remote input.
/// </summary>
public sealed class ServiceUnavailableException(string code, string message, Exception? inner = null)
    : Exception($"Service unavailable: {message} ({code})", inner)
{
    public string Code { get; } = code;

    /// <summary>
    /// True when the service answered with this error (it is reachable); false when it could not
    /// be reached. Without a transport cause the code decides: only <c>service_unavailable</c> and
    /// <c>unauthorized</c> mean the service was not reached.
    /// </summary>
    public bool ServiceResponded => InnerException is IpcClientException transport
        ? transport.ServiceResponded
        : Code is not (IpcErrorCodes.ServiceUnavailable or IpcErrorCodes.Unauthorized);
}

/// <summary>
/// UI-facing adapter over the shared pipe client. It preserves the UI's existing exception contract
/// while the wire implementation lives in Contracts for reuse by the MCP process.
/// </summary>
public sealed class ServicePipeClient(
    string pipeName = IpcPipe.Name,
    TimeSpan? requestTimeout = null) : IServiceRequestClient
{
    private readonly IpcPipeClient _client = new(pipeName, requestTimeout: requestTimeout);

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
