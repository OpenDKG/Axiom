// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Privacy;

namespace Axiom.Service.Hosting.Dns;

/// <summary>
/// Keeps a running <see cref="DnsProxyServer"/> pointed at live upstreams when the platform
/// redirects system DNS to it (<see cref="IPrivacyDnsPlatform.RediscoversUpstreams"/>). The
/// system resolvers are re-read every <see cref="PollInterval"/>, or every
/// <see cref="FailingPollInterval"/> while the proxy reports an upstream failure streak of at
/// least <see cref="FailureStreakThreshold"/>. A changed set is swapped in without touching the
/// listeners. The pure decision lives in <see cref="Decide"/> so it is unit-tested.
/// </summary>
public static class UpstreamRediscovery
{
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);

    public static readonly TimeSpan FailingPollInterval = TimeSpan.FromSeconds(2);

    public const int FailureStreakThreshold = 3;

    /// <summary>
    /// The upstream list to switch to, or null to keep the current one. Loopback addresses are
    /// never upstreams (they are this resolver: the platform returns the saved pre-redirect
    /// servers instead); an empty or loopback-only discovery keeps the current list, because
    /// "nothing found" during a network transition must not drop a working upstream. The same
    /// set in the same order is not a change, however long the failure streak is.
    /// </summary>
    public static IReadOnlyList<IPEndPoint>? Decide(
        IReadOnlyList<IPEndPoint> current,
        IReadOnlyList<IPEndPoint> discovered)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(discovered);

        var candidates = new List<IPEndPoint>();
        foreach (var endpoint in discovered)
        {
            if (!IPAddress.IsLoopback(endpoint.Address) && !candidates.Contains(endpoint))
            {
                candidates.Add(endpoint);
            }
        }

        if (candidates.Count == 0)
        {
            return null;
        }

        return candidates.SequenceEqual(current) ? null : candidates;
    }

    /// <summary>Whether a discovery is due at <paramref name="now"/>.</summary>
    public static bool IsDue(DateTimeOffset lastDiscovery, DateTimeOffset now, long failureStreak)
    {
        var interval = failureStreak >= FailureStreakThreshold ? FailingPollInterval : PollInterval;
        return now - lastDiscovery >= interval;
    }

    /// <summary>
    /// Whether a running resolver should be watched at all: the platform redirects system DNS to it
    /// and the user configured no explicit upstream. An explicit upstream (IP, list or DoH URL) is
    /// never replaced by discovery.
    /// </summary>
    public static bool ShouldWatch(IPrivacyDnsPlatform platform, PrivacyShieldSettings settings)
    {
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(settings);
        return platform.RediscoversUpstreams && string.IsNullOrWhiteSpace(settings.UpstreamDns);
    }

    /// <summary>
    /// One discovery: re-reads the system resolvers, applies the start path's selection
    /// (<see cref="DnsUpstream.SelectSystemTargets"/> with the settings' <c>EncryptDnsViaDoh</c>) and
    /// swaps the result into <paramref name="server"/> when it differs from the targets in use.
    /// Returns true when the upstreams changed. Nothing is discovered or changed when an explicit
    /// upstream is configured; an empty or loopback-only discovery keeps the current targets;
    /// discovery errors are logged and leave the server untouched.
    /// </summary>
    public static bool Rediscover(
        DnsProxyServer server,
        IPrivacyDnsPlatform platform,
        Action<string> log,
        PrivacyShieldSettings settings)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(settings);

        if (!string.IsNullOrWhiteSpace(settings.UpstreamDns))
        {
            return false;
        }

        var streak = server.UpstreamFailureStreak;
        IReadOnlyList<IPEndPoint> discovered;
        try
        {
            discovered = platform.DiscoverUpstreams();
        }
#pragma warning disable CA1031 // A failed tool call must not end the watch; the next tick retries.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            log($"upstream rediscovery failed: {exception.Message}");
            return false;
        }

        // Loopback-free, de-duplicated discovery; null when nothing usable was found.
        var candidates = Decide([], discovered);
        var replacement = candidates is null
            ? null
            : DnsUpstream.SelectSystemTargets(candidates, settings.EncryptDnsViaDoh);
        if (replacement is null || replacement.Count == 0 || replacement.SequenceEqual(server.Targets))
        {
            if (streak >= FailureStreakThreshold)
            {
                log($"upstreams unchanged ({server.Upstream}) after {streak} consecutive failures");
            }

            return false;
        }

        var previous = server.Upstream;
        server.UpdateTargets(replacement);
        log($"upstreams changed: {previous} -> {server.Upstream}" +
            (streak > 0 ? $" (after {streak} consecutive failures)" : string.Empty));
        return true;
    }

    /// <summary>
    /// Watches <paramref name="server"/> until <paramref name="cancellationToken"/> fires: ticks
    /// every <see cref="FailingPollInterval"/>, runs <see cref="Rediscover"/> when
    /// <see cref="IsDue"/>. Only platforms that redirect system DNS start this.
    /// </summary>
    public static async Task WatchAsync(
        DnsProxyServer server,
        IPrivacyDnsPlatform platform,
        Action<string> log,
        PrivacyShieldSettings settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(settings);

        log($"upstream rediscovery active: every {PollInterval.TotalSeconds:0} s, every {FailingPollInterval.TotalSeconds:0} s after {FailureStreakThreshold} consecutive upstream failures");
        var last = DateTimeOffset.UtcNow;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(FailingPollInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            var now = DateTimeOffset.UtcNow;
            if (!IsDue(last, now, server.UpstreamFailureStreak))
            {
                continue;
            }

            last = now;
            Rediscover(server, platform, log, settings);
        }
    }
}
