// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;

namespace Axiom.Presentation;

/// <summary>One observed service state. No value is invented when the service is offline.</summary>
public sealed record ServiceStatusSnapshot
{
    public required bool IsConnected { get; init; }

    public ServiceCapabilities? Capabilities { get; init; }

    public ServiceHealth? Health { get; init; }

    public string? LastError { get; init; }
}

/// <summary>
/// Queries the local service capabilities and health. It never retries silently with a different
/// command, never writes, and reports an offline service as offline.
/// </summary>
public sealed class ServiceStatusProbe(IServiceRequestClient client)
{
    public async Task<ServiceStatusSnapshot> ProbeAsync(CancellationToken cancellationToken)
    {
        try
        {
            var capabilities = await client
                .SendAsync<ServiceCapabilities>(IpcCommandTypes.Capabilities, null, cancellationToken)
                .ConfigureAwait(false);
            var health = await client
                .SendAsync<ServiceHealth>(IpcCommandTypes.ServiceHealth, null, cancellationToken)
                .ConfigureAwait(false);

            return new ServiceStatusSnapshot
            {
                IsConnected = true,
                Capabilities = capabilities,
                Health = health,
            };
        }
        catch (ServiceUnavailableException exception)
        {
            return new ServiceStatusSnapshot
            {
                IsConnected = false,
                LastError = exception.Message,
            };
        }
#pragma warning disable CA1031 // A status probe must not crash the shell on an unexpected transport error.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return new ServiceStatusSnapshot
            {
                IsConnected = false,
                LastError = exception.Message,
            };
        }
    }
}
