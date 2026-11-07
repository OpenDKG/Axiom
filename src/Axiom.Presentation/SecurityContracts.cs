// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Optional setup forms used by the Security page. Returning null means the user cancelled and
/// nothing may be written.
/// </summary>
public interface ISecurityDialogService
{
    Task<ReputationSettings?> EditReputationAsync(
        ReputationSettings current,
        CancellationToken cancellationToken);

    Task<CommunityFeedSettings?> EditCommunityAsync(
        CommunityFeedSettings current,
        CancellationToken cancellationToken);

    /// <summary>
    /// Null cancels; true installs all hooks; false selects the partial boundary that changes no
    /// agent file.
    /// </summary>
    Task<bool?> ChooseAgentHookInstallationAsync(CancellationToken cancellationToken);
}

public sealed class UnsupportedSecurityDialogs : ISecurityDialogService
{
    public Task<ReputationSettings?> EditReputationAsync(
        ReputationSettings current,
        CancellationToken cancellationToken) => Task.FromResult<ReputationSettings?>(null);

    public Task<CommunityFeedSettings?> EditCommunityAsync(
        CommunityFeedSettings current,
        CancellationToken cancellationToken) => Task.FromResult<CommunityFeedSettings?>(null);

    public Task<bool?> ChooseAgentHookInstallationAsync(CancellationToken cancellationToken) =>
        Task.FromResult<bool?>(null);
}

/// <summary>Shell actions requested by a page, never executed by portable code directly.</summary>
public interface IShellActions
{
    void Restart();

    void Shutdown();
}

public sealed class UnsupportedShellActions : IShellActions
{
    public void Restart()
    {
    }

    public void Shutdown()
    {
    }
}
