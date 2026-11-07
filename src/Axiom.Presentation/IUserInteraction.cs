// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Host services the portable pages may request. Every implementation must show the real result
/// and must not silently perform a destructive action.
/// </summary>
public interface IUserInteraction
{
    /// <summary>Explicit confirmation for one change. Returns false when the user declines.</summary>
    Task<bool> ConfirmAsync(
        string title,
        string message,
        string confirmLabel,
        bool destructive,
        CancellationToken cancellationToken);

    Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken);

    /// <summary>Native save dialog. Returns null when the user cancels.</summary>
    Task<string?> PickSaveFileAsync(
        string suggestedFileName,
        string extension,
        string typeName,
        CancellationToken cancellationToken);

    /// <summary>Native open dialog. Returns null when the user cancels.</summary>
    Task<string?> PickOpenFileAsync(
        string title,
        string extension,
        string typeName,
        CancellationToken cancellationToken);

    Task CopyTextAsync(string text, CancellationToken cancellationToken);

    Task OpenExternalAsync(string url, CancellationToken cancellationToken);
}
