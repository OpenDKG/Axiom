// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Ipc;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Row actions shared by connection lists: block the executable through Axiom Shield and end a
/// process after an explicit confirmation. Failures come back as text instead of exceptions so any
/// page can show them in its status line.
/// </summary>
public sealed class ConnectionActionService(
    IServiceRequestClient? client,
    IUserInteraction ui,
    IProcessActions processes)
{
    private readonly FirewallDefaultsStore _defaults = FirewallDefaultsStore.Shared;

    public bool CanWrite => client is not null;

    public async Task<string> BlockAsync(string appName, string? path, FirewallDirection direction)
    {
        if (client is null)
        {
            return "Firewall writes require the local service.";
        }

        if (string.IsNullOrWhiteSpace(path) || path == "—")
        {
            return "The executable path is not readable; a path-bound rule cannot be created.";
        }

        var directionText = direction == FirewallDirection.Outbound ? "outbound" : "inbound";
        var confirmed = await ui.ConfirmAsync(
            "Axiom firewall write",
            $"Create a {PlatformText.Firewall} block rule for {appName} ({directionText})?\n\n" +
            "The rule is owned by Axiom and can be removed from the Firewall page.",
            "Create rule",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return "Block cancelled.";
        }

        var defaults = _defaults.Load();
        var profiles = defaults.Profiles == FirewallProfile.None ? FirewallProfile.All : defaults.Profiles;
        var protocol = defaults.Protocol;
        var ports = protocol == NetworkProtocol.Any ? null : defaults.RemotePorts;

        var spec = new RuleSpec
        {
            ManagedRuleId = RuleIdentity.ForApp(path, direction),
            AppPath = path,
            Direction = direction,
            Action = FirewallAction.Block,
            Profiles = profiles,
            Protocol = protocol,
            RemoteAddresses = SplitAddresses(defaults.RemoteAddresses),
            RemotePorts = string.IsNullOrWhiteSpace(ports) ? null : ports,
            CreatedBy = Environment.UserName,
            Description = $"Axiom block for {appName}",
        };

        try
        {
            var result = await client
                .SendAsync<RuleApplyResult>(IpcCommandTypes.RuleApply, spec, CancellationToken.None)
                .ConfigureAwait(true);

            return result.Success
                ? $"Block applied for {appName} ({directionText}); verified at {result.VerifiedUtc:HH:mm:ss}."
                : $"Block failed: {result.ErrorCode} — {result.ErrorMessage}";
        }
        catch (ServiceUnavailableException exception)
        {
            return exception.Message;
        }
#pragma warning disable CA1031 // Row actions must report an IPC failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return $"Block failed: {exception.Message}";
        }
    }

    public async Task<string> EndTaskAsync(string appName, IReadOnlyList<int> processIds)
    {
        if (processIds.Count == 0)
        {
            return "This row has no live PID to end.";
        }

        var confirmed = await ui.ConfirmAsync(
            "End task",
            $"End {appName} (PID {string.Join(", ", processIds)})?\n\nUnsaved work in that process will be lost.",
            "End task",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return "End task cancelled.";
        }

        var ended = processes.EndProcesses(processIds);
        return ended == 0
            ? $"No process could be ended for {appName}. It may already be gone, or access was denied."
            : $"Ended {ended} process(es) for {appName}.";
    }

    private static string[] SplitAddresses(string value) =>
        value.Split(
            [',', ';', ' '],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
