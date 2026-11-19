// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>
/// On Linux the axiomd daemon points every systemd-resolved link at the Privacy Shield loopback
/// resolver itself (<c>resolvectl dns/domain</c>) while the resolver runs, and restores the saved
/// servers when it stops (docs/LINUX_ARCHITECTURE.md §5). The desktop therefore never changes DNS;
/// both actions explain that instead of pretending to succeed.
/// </summary>
public sealed class LinuxDnsAdapterHelper : IDnsAdapterHelper
{
    public static string Explanation => PlatformText.DaemonDnsNote;

    public Task<int> EnableAsync(string interfaceAlias, string resolverAddress, CancellationToken cancellationToken) =>
        Task.FromException<int>(new NotSupportedException(Explanation));

    public Task<int> RestoreAsync(CancellationToken cancellationToken) =>
        Task.FromException<int>(new NotSupportedException(Explanation));
}
