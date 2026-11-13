// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Text.Json;

namespace Axiom.Contracts.Ipc;

/// <summary>Typed failure from the local service pipe. The message is safe to show to the user.</summary>
public sealed class IpcClientException(string code, string message, Exception? inner = null)
    : Exception(message, inner)
{
    public string Code { get; } = code;
}

/// <summary>
/// Local-only pipe client shared by the desktop UI and the MCP adapter. It connects per request, so
/// an offline or restarted service is picked up on the next call without stale state.
/// </summary>
public sealed class IpcPipeClient(
    string pipeName = IpcPipe.Name,
    TimeSpan? connectTimeout = null,
    TimeSpan? requestTimeout = null)
{
    private static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(5);

    public async Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(requestTimeout ?? DefaultRequestTimeout);

        try
        {
            await using var pipe = new NamedPipeClientStream(
                ".",
                IpcPipe.Resolve(pipeName),
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await pipe.ConnectAsync(
                (int)(connectTimeout ?? DefaultConnectTimeout).TotalMilliseconds,
                timeout.Token).ConfigureAwait(false);

            var envelope = new IpcEnvelope
            {
                Type = command,
                Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, IpcJson.Options),
            };

            await IpcLineProtocol
                .WriteLineAsync(pipe, JsonSerializer.Serialize(envelope, IpcJson.Options), timeout.Token)
                .ConfigureAwait(false);

            var line = await new IpcLineReader(pipe)
                .ReadLineAsync(IpcProtocol.MaxResponseBytes, timeout.Token)
                .ConfigureAwait(false)
                ?? throw new IpcClientException(
                    IpcErrorCodes.ServiceUnavailable,
                    "The service closed the pipe without a response.");

            var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options)
                ?? throw new IpcClientException(
                    IpcErrorCodes.InvalidRequest,
                    "The service returned an empty response.");

            if (!response.Ok)
            {
                throw new IpcClientException(
                    response.Error?.Code ?? IpcErrorCodes.InternalError,
                    response.Error?.Message ?? "The service rejected the request.");
            }

            if (response.Result is not { } result)
            {
                throw new IpcClientException(
                    IpcErrorCodes.InvalidRequest,
                    "The service returned no result.");
            }

            return result.Deserialize<T>(IpcJson.Options)
                ?? throw new IpcClientException(
                    IpcErrorCodes.InvalidRequest,
                    $"The service result could not be read as {typeof(T).Name}.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IpcClientException(
                IpcErrorCodes.ServiceUnavailable,
                "The service did not respond in time.");
        }
        catch (TimeoutException exception)
        {
            throw new IpcClientException(
                IpcErrorCodes.ServiceUnavailable,
                "The service did not respond in time.",
                exception);
        }
        catch (JsonException exception)
        {
            throw new IpcClientException(
                IpcErrorCodes.InvalidRequest,
                "The service returned malformed JSON.",
                exception);
        }
        catch (IOException exception)
        {
            throw new IpcClientException(
                IpcErrorCodes.ServiceUnavailable,
                exception.Message,
                exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new IpcClientException(
                IpcErrorCodes.Unauthorized,
                "Access to the service pipe was denied.",
                exception);
        }
    }
}
