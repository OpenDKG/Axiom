// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// On macOS the axiomd daemon points every network service at the Privacy Shield loopback resolver
/// itself (<c>networksetup -setdnsservers</c>) while the resolver runs, and restores the saved
/// servers when it stops (docs/MACOS_ARCHITECTURE.md §1). The desktop therefore never changes DNS;
/// both actions explain that instead of pretending to succeed.
/// </summary>
public sealed class MacDnsAdapterHelper : IDnsAdapterHelper
{
    public const string Explanation =
        "On macOS the Axiom daemon switches system DNS to Privacy Shield automatically while the " +
        "resolver runs and restores the previous DNS servers when it stops. No manual change is needed.";

    public Task<int> EnableAsync(string interfaceAlias, string resolverAddress, CancellationToken cancellationToken) =>
        Task.FromException<int>(new NotSupportedException(Explanation));

    public Task<int> RestoreAsync(CancellationToken cancellationToken) =>
        Task.FromException<int>(new NotSupportedException(Explanation));
}
