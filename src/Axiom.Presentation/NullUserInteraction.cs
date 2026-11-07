// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Safe placeholder for a host that did not supply UI services. Confirmations are declined and
/// exports are cancelled; it never pretends that an action succeeded.
/// </summary>
public sealed class NullUserInteraction : IUserInteraction
{
    public Task<bool> ConfirmAsync(
        string title,
        string message,
        string confirmLabel,
        bool destructive,
        CancellationToken cancellationToken) => Task.FromResult(false);

    public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task<string?> PickSaveFileAsync(
        string suggestedFileName,
        string extension,
        string typeName,
        CancellationToken cancellationToken) => Task.FromResult<string?>(null);

    public Task CopyTextAsync(string text, CancellationToken cancellationToken) =>
        throw new NotSupportedException("The host does not provide clipboard access.");

    public Task OpenExternalAsync(string url, CancellationToken cancellationToken) =>
        throw new NotSupportedException("The host does not provide external link access.");
}
