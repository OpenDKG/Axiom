// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Core.Firewall;
using Axiom.Persistence;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// Owns the machine recovery snapshot and the privileged restore. Capture is idempotent and never
/// overwrites an existing baseline; restore re-reads the validated file and only touches adapters
/// and rules recorded in it. Both operations are serialised, so a repeated or concurrent restore
/// cannot interleave with itself.
/// </summary>
public sealed partial class NetworkRecoveryController : IDisposable
{
    private readonly INetworkRecoveryDnsAdapter _dns;
    private readonly IOwnedRuleRecoveryAdapter _firewall;
    private readonly Func<bool> _isWriteAuthorized;
    private readonly Func<bool> _isProtectionActive;
    private readonly Func<bool>? _isLoopbackResolverExpected;
    private readonly Func<DateTimeOffset> _clock;
    private readonly string _snapshotPath;
    private readonly HistoryStore? _history;
    private readonly ILogger<NetworkRecoveryController> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public NetworkRecoveryController(
        INetworkRecoveryDnsAdapter dns,
        IOwnedRuleRecoveryAdapter firewall,
        Func<bool> isWriteAuthorized,
        Func<bool> isProtectionActive,
        string snapshotPath,
        HistoryStore? history = null,
        ILogger<NetworkRecoveryController>? logger = null,
        Func<DateTimeOffset>? clock = null,
        Func<bool>? isLoopbackResolverExpected = null)
    {
        ArgumentNullException.ThrowIfNull(dns);
        ArgumentNullException.ThrowIfNull(firewall);
        ArgumentNullException.ThrowIfNull(isWriteAuthorized);
        ArgumentNullException.ThrowIfNull(isProtectionActive);
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotPath);

        _dns = dns;
        _firewall = firewall;
        _isWriteAuthorized = isWriteAuthorized;
        _isProtectionActive = isProtectionActive;
        _snapshotPath = snapshotPath;
        _history = history;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<NetworkRecoveryController>.Instance;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _isLoopbackResolverExpected = isLoopbackResolverExpected;
    }

    public string SnapshotPath => _snapshotPath;

    public void Dispose() => _gate.Dispose();

    [LoggerMessage(EventId = 4301, Level = LogLevel.Information,
        Message = "Network recovery baseline captured by {Actor}: {Adapters} adapter(s), {Rules} Axiom rule(s), protection active {ProtectionActive}")]
    private static partial void LogCaptured(
        ILogger logger,
        string actor,
        int adapters,
        int rules,
        bool protectionActive);

    [LoggerMessage(EventId = 4302, Level = LogLevel.Information,
        Message = "Network recovery restore by {Actor}: {Adapters} adapter(s), {Rules} rule(s), verified {Verified}")]
    private static partial void LogRestored(
        ILogger logger,
        string actor,
        int adapters,
        int rules,
        bool verified);

    [LoggerMessage(EventId = 4303, Level = LogLevel.Error, Message = "Network recovery failed: {Code}")]
    private static partial void LogFailure(ILogger logger, string code, Exception exception);

    /// <summary>
    /// Captures DNS and Axiom-owned rules once. A valid existing snapshot is the baseline and is
    /// kept; a corrupt or unreadable file is reported instead of being silently replaced.
    /// </summary>
    public async Task<NetworkRecoveryCaptureResult> CaptureAsync(
        string actor,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (MachineStateSecurity.IsReparsePointInPath(_snapshotPath))
            {
                return CaptureFailure(
                    NetworkRecoveryStatus.Failed,
                    "snapshot.path_unsafe",
                    "The recovery snapshot path contains a junction or symbolic link, so no baseline was written.");
            }

            var existing = NetworkRecoverySnapshotStore.Read(_snapshotPath);
            switch (existing.Status)
            {
                case NetworkRecoverySnapshotReadStatus.Valid:
                    return CaptureResult(NetworkRecoveryStatus.AlreadyCaptured, existing.Snapshot!, persisted: true);

                case NetworkRecoverySnapshotReadStatus.Corrupt:
                    return CaptureFailure(
                        NetworkRecoveryStatus.SnapshotCorrupt,
                        "snapshot.corrupt",
                        existing.Error ?? "The saved recovery snapshot is corrupt.");

                case NetworkRecoverySnapshotReadStatus.Unreadable:
                    return CaptureFailure(
                        NetworkRecoveryStatus.Failed,
                        "snapshot.unreadable",
                        existing.Error ?? "The saved recovery snapshot could not be read.");
            }

            IReadOnlyList<NetworkAdapterDnsState> adapters;
            try
            {
                adapters = _dns.CaptureDns();
            }
            catch (NetworkRecoveryPlatformException exception)
            {
                LogFailure(_logger, exception.Code, exception);
                return CaptureFailure(NetworkRecoveryStatus.Failed, exception.Code, exception.Message);
            }

            // A missing baseline captured while the local resolver is expected would record the
            // loopback address as the "good" state and restore the outage later.
            if (_isLoopbackResolverExpected?.Invoke() == true &&
                adapters.Any(adapter =>
                    IsLoopbackOnly(adapter.Ipv4Servers) || IsLoopbackOnly(adapter.Ipv6Servers)))
            {
                return CaptureFailure(
                    NetworkRecoveryStatus.Failed,
                    "snapshot.loopback_state",
                    "Adapter DNS already points at the Axiom loopback resolver. Stop Privacy Shield before resetting the recovery baseline.");
            }

            IReadOnlyList<ManagedRule> ownedRules;
            try
            {
                ownedRules = await _firewall.ListOwnedRulesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is
                         InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
            {
                LogFailure(_logger, "firewall.capture_failed", exception);
                return CaptureFailure(
                    NetworkRecoveryStatus.Failed,
                    "firewall.capture_failed",
                    $"Axiom-owned firewall rules could not be read: {exception.Message}");
            }

            var rules = new List<NetworkOwnedRuleState>();
            var identities = new HashSet<(Guid Id, FirewallDirection Direction)>();
            foreach (var rule in ownedRules)
            {
                // A rule only enters the snapshot when identity AND OS ownership metadata agree.
                if (!OwnedRuleOwnership.IsRecoverable(rule) ||
                    !identities.Add((rule.ManagedRuleId, rule.Spec.Direction)))
                {
                    continue;
                }

                rules.Add(new NetworkOwnedRuleState
                {
                    ManagedRuleId = rule.ManagedRuleId,
                    Direction = rule.Spec.Direction,
                    OwnershipGroup = rule.OwnershipGroup ?? OwnedRuleOwnership.GroupName,
                });
            }

            var snapshot = new NetworkRecoverySnapshot
            {
                CapturedUtc = _clock(),
                ProtectionWasActive = _isProtectionActive(),
                Adapters = adapters,
                Rules = rules,
            };

            if (!NetworkRecoverySnapshotStore.TryWrite(_snapshotPath, snapshot, out var error))
            {
                return CaptureFailure(
                    NetworkRecoveryStatus.Failed,
                    "snapshot.write_failed",
                    error ?? "The recovery snapshot could not be written.");
            }

            if (OperatingSystem.IsWindows() &&
                string.Equals(
                    Path.GetFullPath(_snapshotPath),
                    Path.GetFullPath(NetworkRecoverySnapshotStore.DefaultPath),
                    StringComparison.OrdinalIgnoreCase))
            {
                MachineStateSecurity.HardenProgramData();
            }

            LogCaptured(_logger, actor, adapters.Count, rules.Count, snapshot.ProtectionWasActive);
            return CaptureResult(NetworkRecoveryStatus.Succeeded, snapshot, persisted: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Restores DNS and removes only captured Axiom-owned rules. Every changed item is read back;
    /// a partial failure is reported instead of being presented as success.
    /// </summary>
    public Task<NetworkRecoveryRestoreResult> RestoreAsync(
        string actor,
        CancellationToken cancellationToken) =>
        RestoreCoreAsync(actor, restoreRules: true, cancellationToken);

    /// <summary>
    /// Watchdog path: repairs DNS only and never removes a firewall rule, so an intentionally
    /// enabled Axiom Shield is not disabled just because the desktop or the resolver stopped.
    /// </summary>
    public Task<NetworkRecoveryRestoreResult> RestoreDnsOnlyAsync(
        string actor,
        CancellationToken cancellationToken) =>
        RestoreCoreAsync(actor, restoreRules: false, cancellationToken);

    private async Task<NetworkRecoveryRestoreResult> RestoreCoreAsync(
        string actor,
        bool restoreRules,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);

        if (!_isWriteAuthorized())
        {
            return RestoreFailure(
                NetworkRecoveryStatus.NotAuthorized,
                "recovery.not_authorized",
                "Network restore requires the elevated Axiom service or an administrator recovery command. Nothing was changed.");
        }

        if (!await _gate.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false))
        {
            return RestoreFailure(
                NetworkRecoveryStatus.Busy,
                "recovery.busy",
                "Another network recovery operation is still running. Nothing was changed.");
        }

        try
        {
            if (MachineStateSecurity.IsReparsePointInPath(_snapshotPath))
            {
                return RestoreFailure(
                    NetworkRecoveryStatus.Failed,
                    "snapshot.path_unsafe",
                    "The recovery snapshot path contains a junction or symbolic link. Nothing was changed.");
            }

            var read = NetworkRecoverySnapshotStore.Read(_snapshotPath);
            switch (read.Status)
            {
                case NetworkRecoverySnapshotReadStatus.Missing:
                    return RestoreFailure(
                        NetworkRecoveryStatus.NoSnapshot,
                        "snapshot.missing",
                        "No saved network state is available. Nothing was changed.");

                case NetworkRecoverySnapshotReadStatus.Corrupt:
                    return RestoreFailure(
                        NetworkRecoveryStatus.SnapshotCorrupt,
                        "snapshot.corrupt",
                        read.Error ?? "The saved network state is corrupt. Nothing was changed.");

                case NetworkRecoverySnapshotReadStatus.Unreadable:
                    return RestoreFailure(
                        NetworkRecoveryStatus.Failed,
                        "snapshot.unreadable",
                        read.Error ?? "The saved network state could not be read. Nothing was changed.");
            }

            var snapshot = read.Snapshot!;
            var problems = new List<NetworkRecoveryProblem>();
            var adaptersRestored = 0;
            var rulesRemoved = 0;
            var rulesAbsent = 0;

            foreach (var adapter in snapshot.Adapters)
            {
                try
                {
                    _dns.ApplyDns(adapter);
                    adaptersRestored++;
                }
                catch (NetworkRecoveryPlatformException exception)
                {
                    problems.Add(new NetworkRecoveryProblem
                    {
                        Code = exception.Code,
                        Message = exception.Message,
                        Item = adapter.InterfaceAlias,
                    });
                }
                catch (Exception exception) when (exception is UnauthorizedAccessException or InvalidOperationException)
                {
                    problems.Add(new NetworkRecoveryProblem
                    {
                        Code = "dns.restore_failed",
                        Message = $"DNS for '{adapter.InterfaceAlias}' was not restored: {exception.Message}",
                        Item = adapter.InterfaceAlias,
                    });
                }
            }

            foreach (var rule in snapshot.Rules)
            {
                if (!restoreRules)
                {
                    // DNS-only watchdog path: firewall rules stay untouched.
                    break;
                }

                var item = $"Axiom::{rule.ManagedRuleId:D}::{DirectionToken(rule.Direction)}";
                try
                {
                    var presence = await _firewall
                        .InspectOwnedRuleAsync(rule.ManagedRuleId, rule.Direction, cancellationToken)
                        .ConfigureAwait(false);

                    if (presence == OwnedRulePresence.Absent)
                    {
                        rulesAbsent++;
                        continue;
                    }

                    if (presence == OwnedRulePresence.ForeignOrChanged)
                    {
                        problems.Add(new NetworkRecoveryProblem
                        {
                            Code = "rule.not_owned",
                            Message = "The rule identity exists but its ownership metadata changed; it was not removed.",
                            Item = item,
                        });
                        continue;
                    }

                    var removal = await _firewall
                        .RemoveCapturedOwnedRuleAsync(rule.ManagedRuleId, rule.Direction, cancellationToken)
                        .ConfigureAwait(false);

                    if (!removal.Success)
                    {
                        problems.Add(new NetworkRecoveryProblem
                        {
                            Code = removal.ErrorCode ?? "rule.remove_failed",
                            Message = removal.ErrorMessage ?? "The Axiom-owned rule could not be removed.",
                            Item = item,
                        });
                        continue;
                    }

                    rulesRemoved++;
                    await AuditRemovalAsync(rule, actor, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is
                             InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
                {
                    problems.Add(new NetworkRecoveryProblem
                    {
                        Code = "rule.remove_failed",
                        Message = $"The Axiom-owned rule was not removed: {exception.Message}",
                        Item = item,
                    });
                }
            }

            _dns.FlushDnsCache();
            var adaptersVerified = VerifyAdapters(snapshot, problems);
            var rulesVerified = rulesRemoved + rulesAbsent;
            var verified = problems.Count == 0 &&
                           adaptersVerified == snapshot.Adapters.Count &&
                           (!restoreRules || rulesVerified == snapshot.Rules.Count);

            var status = verified
                ? NetworkRecoveryStatus.Succeeded
                : adaptersRestored == 0 && rulesRemoved == 0
                    ? NetworkRecoveryStatus.Failed
                    : NetworkRecoveryStatus.PartialFailure;

            LogRestored(_logger, actor, adaptersRestored, rulesRemoved, verified);

            return new NetworkRecoveryRestoreResult
            {
                Status = status,
                AdaptersRestored = adaptersRestored,
                AdaptersVerified = adaptersVerified,
                RulesRemoved = rulesRemoved,
                RulesVerifiedAbsent = rulesVerified,
                Verified = verified,
                CompletedUtc = _clock(),
                Problems = problems,
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private int VerifyAdapters(
        NetworkRecoverySnapshot snapshot,
        List<NetworkRecoveryProblem> problems)
    {
        if (snapshot.Adapters.Count == 0)
        {
            return 0;
        }

        IReadOnlyList<NetworkAdapterDnsState> current;
        try
        {
            current = _dns.CaptureDns();
        }
        catch (NetworkRecoveryPlatformException exception)
        {
            problems.Add(new NetworkRecoveryProblem
            {
                Code = exception.Code,
                Message = $"The restored DNS could not be verified: {exception.Message}",
            });
            return 0;
        }

        var verified = 0;
        foreach (var expected in snapshot.Adapters)
        {
            var actual = current.FirstOrDefault(adapter => adapter.AdapterId == expected.AdapterId);
            if (actual is null)
            {
                problems.Add(new NetworkRecoveryProblem
                {
                    Code = "adapter.not_available",
                    Message = "The adapter is not connected or no longer present, so its DNS could not be verified.",
                    Item = expected.InterfaceAlias,
                });
                continue;
            }

            if (DnsMatches(actual, expected))
            {
                verified++;
                continue;
            }

            problems.Add(new NetworkRecoveryProblem
            {
                Code = "dns.verify_failed",
                Message = "The adapter did not read back with the saved DNS configuration.",
                Item = expected.InterfaceAlias,
            });
        }

        return verified;
    }

    private async Task AuditRemovalAsync(
        NetworkOwnedRuleState rule,
        string actor,
        CancellationToken cancellationToken)
    {
        if (_history is null)
        {
            return;
        }

        try
        {
            await _history.DeleteFirewallRuleAsync(
                rule.ManagedRuleId,
                actor,
                "network.recovery",
                "removed by network recovery",
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is
                     Microsoft.Data.Sqlite.SqliteException or InvalidOperationException or IOException)
        {
            // The OS rule is already gone; a missing audit row must not turn that into a failure.
            LogFailure(_logger, "audit.write_failed", exception);
        }
    }

    private static bool DnsMatches(NetworkAdapterDnsState actual, NetworkAdapterDnsState expected) =>
        actual.Ipv4Mode == expected.Ipv4Mode &&
        actual.Ipv6Mode == expected.Ipv6Mode &&
        SameServers(actual.Ipv4Servers, expected.Ipv4Servers) &&
        SameServers(actual.Ipv6Servers, expected.Ipv6Servers);

    private static bool SameServers(IReadOnlyList<string> left, IReadOnlyList<string> right) =>
        left.Count == right.Count &&
        left.SequenceEqual(right, StringComparer.OrdinalIgnoreCase);

    private static bool IsLoopbackOnly(IReadOnlyList<string> servers) =>
        servers.Count > 0 &&
        servers.All(server =>
            System.Net.IPAddress.TryParse(server, out var address) && System.Net.IPAddress.IsLoopback(address));

    private static NetworkRecoveryCaptureResult CaptureResult(
        NetworkRecoveryStatus status,
        NetworkRecoverySnapshot snapshot,
        bool persisted) => new()
    {
        Status = status,
        CapturedUtc = snapshot.CapturedUtc,
        ProtectionWasActive = snapshot.ProtectionWasActive,
        AdapterCount = snapshot.Adapters.Count,
        RuleCount = snapshot.Rules.Count,
        Persisted = persisted,
    };

    private static NetworkRecoveryCaptureResult CaptureFailure(
        NetworkRecoveryStatus status,
        string code,
        string message) => new()
    {
        Status = status,
        Problems = [new NetworkRecoveryProblem { Code = code, Message = message }],
    };

    private static NetworkRecoveryRestoreResult RestoreFailure(
        NetworkRecoveryStatus status,
        string code,
        string message) => new()
    {
        Status = status,
        CompletedUtc = DateTimeOffset.UtcNow,
        Problems = [new NetworkRecoveryProblem { Code = code, Message = message }],
    };

    private static string DirectionToken(FirewallDirection direction) =>
        direction == FirewallDirection.Outbound ? "OUT" : "IN";
}
