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

            return result.Success && result.State != RuleState.Pending
                ? $"Block applied for {appName} ({directionText}); verified at {result.VerifiedUtc:HH:mm:ss}."
                : RuleApplyResultText.Describe(result, "Block");
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

    public Task<string> EndProcessAsync(string appName, int processId)
    {
        if (processId <= 0)
        {
            return Task.FromResult("This row has no live PID to end.");
        }

        return EndScopedAsync(
            title: "End process (PID)",
            confirmLabel: "End process",
            cancelStatus: "End process cancelled.",
            body: $"End process {appName} (PID {processId})?\n\nUnsaved work in that process will be lost.",
            processIds: [processId],
            targetDescription: $"{appName} (PID {processId})");
    }

    public Task<string> EndApplicationAsync(string appName, IReadOnlyList<int> processIds)
    {
        var liveIds = processIds.Where(pid => pid > 0).Distinct().ToArray();
        if (liveIds.Length == 0)
        {
            return Task.FromResult("This application has no live processes to end.");
        }

        var pidList = string.Join(", ", liveIds);
        return EndScopedAsync(
            title: "End application",
            confirmLabel: "End application",
            cancelStatus: "End application cancelled.",
            body: $"End all running processes for {appName} (PID {pidList})?\n\nUnsaved work in those processes will be lost.",
            processIds: liveIds,
            targetDescription: appName);
    }

    public Task<string> EndTaskAsync(string appName, IReadOnlyList<int> processIds) =>
        processIds.Count == 1
            ? EndProcessAsync(appName, processIds[0])
            : EndApplicationAsync(appName, processIds);

    private async Task<string> EndScopedAsync(
        string title,
        string confirmLabel,
        string cancelStatus,
        string body,
        IReadOnlyList<int> processIds,
        string targetDescription)
    {
        var confirmed = await ui.ConfirmAsync(
            title,
            body,
            confirmLabel,
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return cancelStatus;
        }

        var ended = processes.EndProcesses(processIds);
        return ended == 0
            ? $"No process could be ended for {targetDescription}. It may already be gone, or access was denied."
            : $"Ended {ended} process(es) for {targetDescription}.";
    }

    private static string[] SplitAddresses(string value) =>
        value.Split(
            [',', ';', ' '],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
