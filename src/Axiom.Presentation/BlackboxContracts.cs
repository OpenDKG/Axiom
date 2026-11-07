// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>Focused Blackbox dialogs. They read and write through the local dashboard only.</summary>
public interface IBlackboxDialogService
{
    Task ShowSettingsAsync(BlackboxDashboardClient client, CancellationToken cancellationToken);

    Task ShowLogAsync(string title, string text, CancellationToken cancellationToken);
}

public sealed class UnsupportedBlackboxDialogs : IBlackboxDialogService
{
    public Task ShowSettingsAsync(BlackboxDashboardClient client, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task ShowLogAsync(string title, string text, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
