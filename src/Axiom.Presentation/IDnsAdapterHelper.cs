// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Explicit UAC-gated adapter DNS changes. Implementations must wait for Windows elevation and
/// must never change DNS silently or from a background action.
/// </summary>
public interface IDnsAdapterHelper
{
    Task<int> EnableAsync(string interfaceAlias, string resolverAddress, CancellationToken cancellationToken);

    Task<int> RestoreAsync(CancellationToken cancellationToken);
}

/// <summary>Host without an elevated DNS helper. It reports failure instead of pretending.</summary>
public sealed class UnsupportedDnsAdapterHelper : IDnsAdapterHelper
{
    public Task<int> EnableAsync(string interfaceAlias, string resolverAddress, CancellationToken cancellationToken) =>
        Task.FromResult(-1);

    public Task<int> RestoreAsync(CancellationToken cancellationToken) => Task.FromResult(-1);
}
