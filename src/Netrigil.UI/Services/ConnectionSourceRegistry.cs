// SPDX-License-Identifier: GPL-3.0-or-later
using Netrigil.Contracts.Monitoring;

namespace Netrigil.UI.Services;

/// <summary>
/// Composition hook. The Desktop host registers the real Windows source before the WPF
/// application starts; the UI project itself never references Windows APIs.
/// </summary>
public static class ConnectionSourceRegistry
{
    public static IConnectionSnapshotSource? Source { get; set; }

    public static bool IsLive => Source is not null;

    public static bool IsServiceMode => Source is ServiceSnapshotSource;

    public static IConnectionSnapshotSource Resolve() => Source ?? new DemoConnectionSnapshotSource();
}
