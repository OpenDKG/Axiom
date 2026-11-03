// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using Netpetra.Contracts.Ipc;

namespace Netpetra.UI.Services;

public sealed class ServiceUnavailableException(string code, string message, Exception? inner = null)
    : Exception($"Service unavailable: {message} ({code})", inner);

/// <summary>
/// Local-only pipe client used by the UI. Connects per request, so an offline or restarted service
/// is picked up on the next poll without stale state.
/// </summary>
public sealed class ServicePipeClient(string pipeName = IpcPipe.Name)
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);

    public async Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);

        try
        {
            await using var pipe = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds, timeout.Token).ConfigureAwait(false);

            var envelope = new IpcEnvelope
            {
                Type = command,
                Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, IpcJson.Options),
            };

            await IpcLineProtocol
                .WriteLineAsync(pipe, JsonSerializer.Serialize(envelope, IpcJson.Options), timeout.Token)
                .ConfigureAwait(false);

            var reader = new IpcLineReader(pipe);

            var line = await reader
                .ReadLineAsync(IpcProtocol.MaxResponseBytes, timeout.Token)
                .ConfigureAwait(false)
                ?? throw new ServiceUnavailableException(
                    IpcErrorCodes.ServiceUnavailable,
                    "The service closed the pipe without a response.");

            var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options)
                ?? throw new ServiceUnavailableException(
                    IpcErrorCodes.InvalidRequest,
                    "The service returned an empty response.");

            if (!response.Ok)
            {
                var code = response.Error?.Code ?? IpcErrorCodes.InternalError;
                var message = response.Error?.Message ?? "The service rejected the request.";
                throw new ServiceUnavailableException(code, message);
            }

            if (response.Result is not { } result)
            {
                throw new ServiceUnavailableException(
                    IpcErrorCodes.InvalidRequest,
                    "The service returned no result.");
            }

            return result.Deserialize<T>(IpcJson.Options)
                ?? throw new ServiceUnavailableException(
                    IpcErrorCodes.InvalidRequest,
                    $"The service result could not be read as {typeof(T).Name}.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ServiceUnavailableException(
                IpcErrorCodes.ServiceUnavailable,
                "The service did not respond in time.");
        }
        catch (TimeoutException exception)
        {
            throw new ServiceUnavailableException(
                IpcErrorCodes.ServiceUnavailable,
                "The service did not respond in time.",
                exception);
        }
        catch (IOException exception)
        {
            throw new ServiceUnavailableException(
                IpcErrorCodes.ServiceUnavailable,
                exception.Message,
                exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new ServiceUnavailableException(
                IpcErrorCodes.Unauthorized,
                "Access to the service pipe was denied.",
                exception);
        }
    }
}
