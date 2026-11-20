// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Threat;

namespace Axiom.Presentation;

/// <summary>Focused Blackbox dialogs. They read and write through the local dashboard only.</summary>
public interface IBlackboxDialogService
{
    Task ShowSettingsAsync(BlackboxDashboardClient client, CancellationToken cancellationToken);

    Task ShowLogAsync(string title, string text, CancellationToken cancellationToken);

    Task<ThreatShareEnqueueRequest?> PromptManualThreatIndicatorAsync(CancellationToken cancellationToken);

    Task<ThreatShareVerifyRequest?> PromptVerifyThreatCandidateAsync(
        ThreatShareCandidate candidate,
        CancellationToken cancellationToken);
}

public sealed class UnsupportedBlackboxDialogs : IBlackboxDialogService
{
    public Task ShowSettingsAsync(BlackboxDashboardClient client, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task ShowLogAsync(string title, string text, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task<ThreatShareEnqueueRequest?> PromptManualThreatIndicatorAsync(CancellationToken cancellationToken) =>
        Task.FromResult<ThreatShareEnqueueRequest?>(null);

    public Task<ThreatShareVerifyRequest?> PromptVerifyThreatCandidateAsync(
        ThreatShareCandidate candidate,
        CancellationToken cancellationToken) =>
        Task.FromResult<ThreatShareVerifyRequest?>(null);
}
