// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;

namespace Axiom.Core.Enforcement;

/// <summary>
/// Sends one bounded evaluation request to the local Axiom service. Implementations must return
/// <c>null</c> when the service is unavailable; the adapter then sends no deny and the host keeps its
/// current mode.
/// </summary>
public interface IEnforcementDecisionTransport
{
    Task<EnforcementVerdictDto?> EvaluateAsync(
        EnforcementEvaluateRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Same-user named-pipe transport. No HTTP, no remote endpoint, no generic execution.</summary>
public sealed class PipeEnforcementDecisionTransport(IpcPipeClient? client = null)
    : IEnforcementDecisionTransport
{
    private readonly IpcPipeClient _client = client ?? new IpcPipeClient();

    public async Task<EnforcementVerdictDto?> EvaluateAsync(
        EnforcementEvaluateRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            return await _client
                .SendAsync<EnforcementVerdictDto>(
                    IpcCommandTypes.EnforcementEvaluate,
                    request,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IpcClientException)
        {
            return null;
        }
    }
}

/// <summary>
/// Maps a real host pre-action event to the canonical request, asks the local service and returns a
/// host-specific deny payload only when the verdict is a block whose strength can actually carry it
/// out. An observation-strength block is advisory and produces no deny.
/// </summary>
public sealed class HostEnforcementAdapter(IEnforcementDecisionTransport transport)
{
    private readonly IEnforcementDecisionTransport _transport =
        transport ?? throw new ArgumentNullException(nameof(transport));

    public async Task<string?> BuildDenyAsync(
        HostHarness host,
        string agentId,
        string? sessionId,
        string? toolName,
        string? target,
        string? processPath,
        string requestId,
        bool hostSupportsDeny,
        BlackboxGuardSignal? guard,
        DateTimeOffset utcTime,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);

        var request = new EnforcementEvaluateRequest
        {
            RequestId = requestId,
            AgentId = agentId,
            SessionId = sessionId,
            Kind = HostDecisionMapping.MapToolKind(toolName).ToString(),
            Target = target,
            ProcessPath = processPath,
            UtcTime = utcTime,
            GuardAvailable = guard?.IsAvailable ?? false,
            GuardBlock = guard?.IsBlock ?? false,
            GuardSignalId = guard?.SignalId,
            HostSupportsDeny = hostSupportsDeny,
        };

        var verdict = await _transport.EvaluateAsync(request, cancellationToken).ConfigureAwait(false);
        if (verdict is null || !verdict.CanEnforce)
        {
            return null;
        }

        return Enum.TryParse<EnforcementDecision>(verdict.Decision, ignoreCase: true, out var decision)
            ? HostDecisionMapping.ToHostResponse(host, decision, "Blocked by Axiom policy.")
            : null;
    }
}
