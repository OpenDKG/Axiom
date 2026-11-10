// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;

namespace Axiom.Service;

public static partial class ServiceInfo
{
    public const string ServiceName = "Axiom";

    public const string DisplayName = "Axiom";

    /// <summary>Set explicitly at process start so uptime is not affected by lazy type loading.</summary>
    public static DateTimeOffset StartedUtc { get; private set; } = DateTimeOffset.UtcNow;

    public static void MarkStarted() => StartedUtc = DateTimeOffset.UtcNow;

    public static string Milestone => ProductMilestone.Current;
}
