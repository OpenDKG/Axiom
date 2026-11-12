// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.NetworkRecovery;

namespace Axiom.Presentation;

/// <summary>
/// Typed desktop client for the privileged recovery commands. It never sends adapters, DNS servers
/// or rule names; the service captures and validates machine state itself.
/// </summary>
public interface INetworkRecoveryClient
{
    Task<NetworkRecoveryCaptureResult> CaptureAsync(CancellationToken cancellationToken);

    Task<NetworkRecoveryRestoreResult> RestoreAsync(CancellationToken cancellationToken);
}

public sealed class NetworkRecoveryClient : INetworkRecoveryClient
{
    /// <summary>Restore touches several adapters and rules, so it needs more than the UI default.</summary>
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(60);

    private readonly IServiceRequestClient _client;

    public NetworkRecoveryClient(IServiceRequestClient? client = null)
    {
        _client = client ?? new ServicePipeClient(requestTimeout: DefaultRequestTimeout);
    }

    public async Task<NetworkRecoveryCaptureResult> CaptureAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await _client
                .SendAsync<NetworkRecoveryCaptureResult>(
                    IpcCommandTypes.NetworkRecoveryCapture,
                    payload: null,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (ServiceUnavailableException exception)
        {
            return new NetworkRecoveryCaptureResult
            {
                Status = StatusFor(exception.Code),
                Problems = [Problem(exception)],
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return UnavailableCapture();
        }
    }

    public async Task<NetworkRecoveryRestoreResult> RestoreAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _client
                .SendAsync<NetworkRecoveryRestoreResult>(
                    IpcCommandTypes.NetworkRecoveryRestore,
                    payload: null,
                    cancellationToken)
                .ConfigureAwait(false);

            return result.Verified || result.Status != NetworkRecoveryStatus.Succeeded
                ? result
                : result with
                {
                    // A success that was not read back is reported as incomplete, never as success.
                    Status = NetworkRecoveryStatus.PartialFailure,
                    Problems =
                    [
                        .. result.Problems,
                        new NetworkRecoveryProblem
                        {
                            Code = "restore.not_verified",
                            Message = "The service reported success without a read-back verification.",
                        },
                    ],
                };
        }
        catch (ServiceUnavailableException exception)
        {
            return new NetworkRecoveryRestoreResult
            {
                Status = StatusFor(exception.Code),
                CompletedUtc = DateTimeOffset.UtcNow,
                Problems = [Problem(exception)],
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new NetworkRecoveryRestoreResult
            {
                Status = NetworkRecoveryStatus.Unavailable,
                CompletedUtc = DateTimeOffset.UtcNow,
                Problems =
                [
                    new NetworkRecoveryProblem
                    {
                        Code = "service.timeout",
                        Message = "The Axiom service did not answer the recovery request in time. Nothing was verified.",
                    },
                ],
            };
        }
    }

    private static NetworkRecoveryStatus StatusFor(string code) => code switch
    {
        IpcErrorCodes.NotSupported or IpcErrorCodes.UnknownCommand or IpcErrorCodes.InvalidRequest =>
            NetworkRecoveryStatus.Incompatible,
        IpcErrorCodes.Unauthorized => NetworkRecoveryStatus.NotAuthorized,
        IpcErrorCodes.ServiceUnavailable => NetworkRecoveryStatus.Unavailable,
        _ => NetworkRecoveryStatus.Failed,
    };

    private static NetworkRecoveryProblem Problem(ServiceUnavailableException exception) => new()
    {
        Code = exception.Code,
        Message = exception.Message,
    };

    private static NetworkRecoveryCaptureResult UnavailableCapture() => new()
    {
        Status = NetworkRecoveryStatus.Unavailable,
        Problems =
        [
            new NetworkRecoveryProblem
            {
                Code = "service.timeout",
                Message = "The Axiom service did not answer the recovery request in time.",
            },
        ],
    };
}
