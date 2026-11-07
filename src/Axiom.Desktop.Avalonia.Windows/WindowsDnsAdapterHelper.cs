// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.Windows;

/// <summary>UAC-gated adapter DNS helper used only after the operator confirms the action.</summary>
public sealed class WindowsDnsAdapterHelper : IDnsAdapterHelper
{
    public Task<int> EnableAsync(
        string interfaceAlias,
        string resolverAddress,
        CancellationToken cancellationToken) =>
        PrivacyShieldDnsHelper.EnableAsync(interfaceAlias, resolverAddress, cancellationToken);

    public Task<int> RestoreAsync(CancellationToken cancellationToken) =>
        PrivacyShieldDnsHelper.RestoreAsync(cancellationToken);
}
