// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Runtime;
using Axiom.Contracts.Privacy;
using Axiom.Service.Hosting.Dns;

namespace Axiom.Service;

/// <summary>
/// Owns the opt-in loopback DNS resolver. On Windows it never changes adapter DNS settings; a user
/// who wants system-wide filtering must point Windows at the displayed loopback resolver explicitly.
/// On macOS the root daemon redirects the network services itself through
/// <see cref="IPrivacyDnsPlatform"/> and restores them when the resolver stops.
/// </summary>
public sealed class PrivacyShieldController : IAsyncDisposable
{
    private readonly PrivacyShieldSettingsStore _store;

    private readonly PrivacyShieldRuleStore _ruleStore;

    private readonly PrivacyShieldSourceUpdater _sourceUpdater;

    private readonly PrivacyShieldBlockedHistoryStore _blockedHistory = new();

    /// <summary>Writes buffered blocked history before the service stops.</summary>
    public void FlushBlockedHistory() => _blockedHistory.Flush();

    private readonly IPrivacyDnsPlatform _dns;

    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Wakes the background source updater when a source was re-enabled (upstream 0.25).</summary>
    private readonly SemaphoreSlim _sourceSyncSignal = new(0, 1);

    private readonly object _rulesGate = new();

    private readonly Dictionary<string, string> _sourceErrors =
        new(StringComparer.OrdinalIgnoreCase);

    private PrivacyShieldSettings _settings;

    private IReadOnlyDictionary<string, (int Entries, DateTimeOffset? Updated)> _sourceTotals =
        new Dictionary<string, (int, DateTimeOffset?)>(StringComparer.OrdinalIgnoreCase);

    private Task? _rulesTask;

    private bool _rulesLoaded;

    private bool _rulesUpdated;

    private PrivacyShieldPolicy? _policy;

    private PrivacyShieldSettings? _policySettings;

    private DnsProxyServer? _server;

    private CancellationTokenSource? _upstreamWatch;

    private string? _lastError;

    public PrivacyShieldController(
        PrivacyShieldSettingsStore store,
        PrivacyShieldRuleStore? ruleStore = null,
        PrivacyShieldSourceUpdater? sourceUpdater = null,
        IPrivacyDnsPlatform? dnsPlatform = null)
    {
        _dns = dnsPlatform ?? ServicePlatform.CreateDefaultPrivacyDnsPlatform();
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _ruleStore = ruleStore ?? new PrivacyShieldRuleStore();
        _sourceUpdater = sourceUpdater ?? new PrivacyShieldSourceUpdater();
        _settings = store.Load();
    }

    /// <summary>Whether the persisted configuration asks the resolver to run.</summary>
    public bool IsEnabled => _settings.Enabled;

    /// <summary>Whether the loopback resolver is listening right now.</summary>
    public bool IsResolverRunning => Volatile.Read(ref _server) is not null;

    /// <summary>
    /// Whether adapter DNS should be kept pointed at the resolver (upstream v0.23.3). The platform
    /// decides what that means; on Windows the service does the work, elsewhere it is a no-op.
    /// </summary>
    public bool ShouldAutoPointAdapterDns =>
        _settings.Enabled &&
        _settings.Port == 53 &&
        (_settings.AutoPointAdapterDns || !string.IsNullOrWhiteSpace(_settings.PreferredAdapterAlias));

    public async Task<PrivacyShieldStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await EnsureRulesLoadedAsync().ConfigureAwait(false);
        return CreateStatus();
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_settings.Enabled)
        {
            await EnsureRulesLoadedAsync().ConfigureAwait(false);
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_settings.Enabled)
            {
                await StartServerLockedAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<PrivacyShieldStatus> ConfigureAsync(
        PrivacyShieldSettings requested,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requested);

        await EnsureRulesLoadedAsync().ConfigureAwait(false);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var normalized = Normalize(requested);
            var previous = _settings;
            var previousWasRunning = _server is not null;

            // Disabled -> disabled: no resolver state to preserve, but a failed write must not
            // leave the requested configuration as the authoritative one.
            if (!normalized.Enabled && !previousWasRunning)
            {
                if (!_store.Save(normalized))
                {
                    _settings = previous;
                    _lastError = "Configuration failed; previous disabled configuration was kept.";
                    return CreateStatus();
                }

                _settings = normalized;
                _lastError = null;
                return CreateStatus();
            }

            // Enabled -> disabled: stop first, then persist. A failed write restores the old
            // resolver and the old in-memory settings.
            if (!normalized.Enabled)
            {
                await StopServerLockedAsync().ConfigureAwait(false);
                if (!_store.Save(normalized))
                {
                    _settings = previous;
                    var restored = await RestorePreviousServerAsync(previous).ConfigureAwait(false);
                    _lastError = restored
                        ? "Configuration failed; previous resolver restored."
                        : "Configuration failed; previous resolver could not be restored.";
                    return CreateStatus();
                }

                _settings = normalized;
                _lastError = null;

                // The adapter may still send DNS to 127.0.0.1. With the resolver stopped that would
                // take name resolution down, so restore the saved DNS without an extra prompt.
                _ = Task.Run(_dns.RestoreIfNeeded);
                return CreateStatus();
            }

            // Enabled -> enabled: start the candidate before persisting. If the port is unchanged,
            // the old listener must be stopped first; otherwise both can coexist briefly.
            var stoppedOldForSamePort = previousWasRunning && normalized.Port == previous.Port;
            if (stoppedOldForSamePort)
            {
                await StopServerLockedAsync().ConfigureAwait(false);
            }

            if (!TryCreateServer(normalized, out var candidate, out var startError, out var startWarning))
            {
                _settings = previous;
                var restored = await RestorePreviousServerAsync(previous).ConfigureAwait(false);
                var recovery = !previous.Enabled
                    ? "previous disabled configuration was kept"
                    : restored
                        ? "previous resolver restored"
                        : "previous resolver could not be restored";
                _lastError = $"Configuration failed; {recovery}. {startError}".Trim();
                return CreateStatus();
            }

            if (!_store.Save(normalized))
            {
                if (candidate is not null)
                {
                    await candidate.DisposeAsync().ConfigureAwait(false);
                }

                _settings = previous;
                var restored = await RestorePreviousServerAsync(previous).ConfigureAwait(false);
                var recovery = !previous.Enabled
                    ? "previous disabled configuration was kept"
                    : restored
                        ? "previous resolver restored"
                        : "previous resolver could not be restored";
                _lastError = $"Configuration failed; {recovery}.";
                return CreateStatus();
            }

            if (previousWasRunning && !stoppedOldForSamePort)
            {
                await StopServerLockedAsync().ConfigureAwait(false);
            }

            _server = candidate;
            _settings = normalized;
            _lastError = CombineWarnings(startWarning, NotifyResolverStarted(candidate));
            EnsureConfiguredAdapterDns();
            if (ShouldAutoUpdateSources())
            {
                SignalSourceSync();
            }

            return CreateStatus();
        }
        finally
        {
            _gate.Release();
        }
    }

    private Task<bool> RestorePreviousServerAsync(PrivacyShieldSettings previous)
    {
        if (!previous.Enabled || _server is not null)
        {
            return Task.FromResult(true);
        }

        if (!TryCreateServer(previous, out var server, out var error, out var warning))
        {
            _server = null;
            _lastError = error;
            return Task.FromResult(false);
        }

        _server = server;
        _lastError = CombineWarnings(warning, NotifyResolverStarted(server));
        return Task.FromResult(true);
    }

    /// <summary>
    /// True when background auto-update is enabled and at least one enabled source has never been
    /// fetched or has aged past <see cref="PrivacyShieldSettings.AutoUpdateIntervalHours"/>.
    /// </summary>
    public bool ShouldAutoUpdateSources(DateTimeOffset? nowUtc = null)
    {
        if (!_settings.Enabled ||
            !_settings.AutoUpdateSources ||
            _settings.EnabledSourceIds.Count == 0)
        {
            return false;
        }

        var utcNow = nowUtc ?? DateTimeOffset.UtcNow;
        var maxAge = TimeSpan.FromHours(Math.Clamp(_settings.AutoUpdateIntervalHours, 1, 168));
        var totals = _sourceTotals;
        foreach (var sourceId in _settings.EnabledSourceIds)
        {
            if (!totals.TryGetValue(sourceId, out var total) ||
                total.Updated is not { } updated ||
                utcNow - updated >= maxAge)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Wakes the background source updater now (a source was re-enabled).</summary>
    internal void SignalSourceSync()
    {
        if (_sourceSyncSignal.CurrentCount == 0)
        {
            try
            {
                _sourceSyncSignal.Release();
            }
            catch (SemaphoreFullException)
            {
            }
        }
    }

    /// <summary>Waits for a source-sync signal, or <paramref name="delay"/>, whichever comes first.</summary>
    internal async Task WaitForSourceSyncOrDelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        await _sourceSyncSignal.WaitAsync(delay, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Keeps the configured or active default-route adapter pointed at the local resolver while the
    /// elevated Windows service is running Privacy Shield on port 53. No-op in non-SYSTEM processes.
    /// The decision and the adapter work are Windows code behind the DNS seam
    /// (<c>WindowsPrivacyDnsPlatform.EnsureConfiguredAdapterDns</c>); other platforms do nothing here.
    /// </summary>
    public void EnsureConfiguredAdapterDns()
    {
        var error = _dns.EnsureConfiguredAdapterDns(_server is not null, _settings);
        if (!string.IsNullOrWhiteSpace(error) && string.IsNullOrWhiteSpace(_lastError))
        {
            _lastError = error;
        }
    }

    public async Task<PrivacyShieldStatus> ClearHistoryAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _blockedHistory.Clear();
            return CreateStatus();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<PrivacyShieldStatus> UpdateSourcesAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var selected = PrivacyShieldSourceCatalog.All
                .Where(source => _settings.EnabledSourceIds.Contains(
                    source.Id,
                    StringComparer.OrdinalIgnoreCase))
                .ToArray();

            var result = await _sourceUpdater.UpdateAsync(selected, cancellationToken).ConfigureAwait(false);
            _sourceErrors.Clear();
            foreach (var source in result.Sources.Where(source => source.Error is not null))
            {
                _sourceErrors[source.Id] = source.Error!;
            }

            if (result.Success)
            {
                if (!_ruleStore.Save(result.Rules))
                {
                    _lastError = "Could not write the compiled Privacy Shield ruleset.";
                }
                else
                {
                    SetRules(result.Rules);
                    _lastError = result.Error;
                    result = null;
                    CompactMemory();
                    if (_settings.Enabled)
                    {
                        await StartServerLockedAsync(cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            else
            {
                _lastError = result.Error ?? "The blocklist update failed; the previous ruleset was kept.";
            }

            return CreateStatus();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopServerLockedAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
            _sourceUpdater.Dispose();
        }
    }

    private async Task StartServerLockedAsync(CancellationToken cancellationToken)
    {
        await StopServerLockedAsync().ConfigureAwait(false);
        if (TryCreateServer(_settings, out var server, out var error, out var warning))
        {
            _server = server;
            _lastError = CombineWarnings(warning, NotifyResolverStarted(server));
            return;
        }

        _server = null;
        _lastError = error;

        // A failed start (port taken, socket error) must not leave the adapter without a resolver.
        _ = Task.Run(_dns.RestoreIfNeeded);
    }

    private bool TryCreateServer(
        PrivacyShieldSettings settings,
        out DnsProxyServer? server,
        out string? error,
        out string? warning)
    {
        server = null;
        error = null;
        warning = null;

        IReadOnlyList<DnsUpstreamTarget> targets;
        if (!string.IsNullOrWhiteSpace(settings.UpstreamDns))
        {
            if (!DnsUpstream.TryParseTargets(settings.UpstreamDns, out targets) ||
                targets.Count == 0)
            {
                error = "The configured upstream DNS address or DoH URL is invalid.";
                return false;
            }
        }
        else
        {
            // Upstream's selection (DoH members only, or the default DoH pair, when EncryptDnsViaDoh),
            // shared with the rediscovery watch so a later swap makes the same choice.
            targets = DnsUpstream.SelectSystemTargets(_dns.DiscoverUpstreams(), settings.EncryptDnsViaDoh);
        }

        if (targets.Count == 0)
        {
            // If the adapter already points at this loopback resolver, system DNS discovery must
            // not leave the machine without an upstream. Keep encrypted public DoH fallbacks and
            // let the user override them explicitly.
            targets = DnsUpstream.DefaultDohTargets();
            warning = _dns.NoUpstreamWarning;
        }

        try
        {
            var policy = GetPolicy(settings);
            server = new DnsProxyServer(
                policy,
                targets,
                settings.Port,
                blocked =>
                {
                    // Public-list-only detections stay local: reporting the same URLhaus domain
                    // from every install would look like independent corroboration on the graph.
                    _blockedHistory.Append(EnrichProvenance(blocked));
                },
                attributor: _dns.Attributor);
            return true;
        }
        catch (Exception exception) when (exception is
                     System.Net.Sockets.SocketException or ArgumentException or InvalidOperationException)
        {
            error = exception.Message;
            return false;
        }
    }

    /// <summary>Lets the platform redirect system DNS to the running resolver (macOS).</summary>
    private string? NotifyResolverStarted(DnsProxyServer? server)
    {
        if (server is null)
        {
            return null;
        }

        StartUpstreamWatch(server);
        try
        {
            return _dns.OnResolverStarted(server.Port);
        }
#pragma warning disable CA1031 // A failed redirect must not take the running resolver down.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return $"System DNS could not be pointed at the resolver: {exception.Message}";
        }
    }

    private static string? CombineWarnings(string? first, string? second) =>
        string.IsNullOrWhiteSpace(first) ? second
        : string.IsNullOrWhiteSpace(second) ? first
        : first + " " + second;

    private async Task StopServerLockedAsync()
    {
        StopUpstreamWatch();
        if (_server is null)
        {
            return;
        }

        await _server.DisposeAsync().ConfigureAwait(false);
        _server = null;
    }

    /// <summary>
    /// Review #7: with the system redirected to this resolver, the upstreams discovered at start
    /// die on a Wi-Fi/VPN change. Only platforms that redirect (macOS) and only when no explicit
    /// upstream is configured (<see cref="UpstreamRediscovery.ShouldWatch"/>); the swap uses the
    /// same selection as the start, so it cannot turn a DoH upstream into a plain one. Windows
    /// behaviour is unchanged.
    /// </summary>
    private void StartUpstreamWatch(DnsProxyServer server)
    {
        StopUpstreamWatch();
        var settings = _settings;
        if (!UpstreamRediscovery.ShouldWatch(_dns, settings))
        {
            return;
        }

        var cancellation = new CancellationTokenSource();
        _upstreamWatch = cancellation;
        _ = UpstreamRediscovery.WatchAsync(
            server,
            _dns,
            message => Console.Error.WriteLine("Privacy Shield DNS: " + message),
            settings,
            cancellation.Token);
    }

    private void StopUpstreamWatch()
    {
        var watch = _upstreamWatch;
        _upstreamWatch = null;
        if (watch is null)
        {
            return;
        }

        watch.Cancel();
        watch.Dispose();
    }

    private Task EnsureRulesLoadedAsync()
    {
        lock (_rulesGate)
        {
            if (_rulesLoaded)
            {
                return Task.CompletedTask;
            }

            // Load and compile the ruleset off the service-startup thread so the pipe, firewall
            // consent, and monitor are ready immediately, then drop the raw list and compact LOH.
            return _rulesTask ??= Task.Run(() =>
            {
                var rules = _ruleStore.Load();
                lock (_rulesGate)
                {
                    if (!_rulesUpdated)
                    {
                        AdoptRulesLocked(rules, _settings);
                    }

                    _rulesLoaded = true;
                }

                rules = [];
                CompactMemory();
            });
        }
    }

    private static void CompactMemory()
    {
        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
    }

    /// <summary>
    /// Compiles and adopts a new ruleset from an explicit update, releasing the temporary list.
    /// </summary>
    private void SetRules(IReadOnlyList<PrivacyShieldStoredRule> rules)
    {
        lock (_rulesGate)
        {
            _rulesUpdated = true;
            _rulesLoaded = true;
            AdoptRulesLocked(rules, _settings);
        }
    }

    private void AdoptRulesLocked(
        IReadOnlyList<PrivacyShieldStoredRule> rules,
        PrivacyShieldSettings settings)
    {
        var totals = new Dictionary<string, (int Entries, DateTimeOffset? Updated)>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            if (!totals.TryGetValue(rule.SourceId, out var total))
            {
                total = (0, null);
            }

            var updated = total.Updated is null || rule.UpdatedUtc > total.Updated
                ? rule.UpdatedUtc
                : total.Updated;
            totals[rule.SourceId] = (total.Entries + 1, updated);
        }

        _sourceTotals = totals;
        _policy = PrivacyShieldPolicy.Create(settings, rules);
        _policySettings = settings;
    }

    /// <summary>
    /// Returns the compiled policy for <paramref name="settings"/>, reusing the compiled catalog
    /// index across settings changes without holding the raw rule list in memory.
    /// </summary>
    private PrivacyShieldPolicy GetPolicy(PrivacyShieldSettings settings)
    {
        lock (_rulesGate)
        {
            var policy = _policy;
            if (policy is not null && ReferenceEquals(_policySettings, settings))
            {
                return policy;
            }

            policy = policy is null
                ? PrivacyShieldPolicy.Create(settings)
                : policy.WithSettings(settings);
            _policy = policy;
            _policySettings = settings;
            return policy;
        }
    }

    private PrivacyShieldBlockedEvent EnrichProvenance(PrivacyShieldBlockedEvent blocked)
    {
        var source = PrivacyShieldSourceCatalog.All.FirstOrDefault(item =>
            string.Equals(item.Id, blocked.SourceId, StringComparison.OrdinalIgnoreCase));
        var sourceVersion = source?.Sha256 ?? string.Empty;
        if (string.IsNullOrWhiteSpace(sourceVersion) &&
            _sourceTotals.TryGetValue(blocked.SourceId, out var total) &&
            total.Updated is { } updated)
        {
            sourceVersion = updated.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        }

        var sourceName = source?.Name ?? blocked.SourceId switch
        {
            "starter" => "Axiom starter rules",
            "custom" => "User blocklist",
            _ => blocked.SourceId,
        };

        return blocked with
        {
            SourceName = sourceName,
            SourceVersion = sourceVersion,
            AxiomVersion = typeof(PrivacyShieldController).Assembly.GetName().Version?.ToString(3)
                           ?? string.Empty,
        };
    }

    private PrivacyShieldStatus CreateStatus()
    {
        if (_server is not null)
        {
            return _server.Snapshot(_settings) with
            {
                Settings = _settings,
                Sources = BuildSourceStatuses(),
                BlockedHistory = _blockedHistory.LoadRecent(),
                LastError = _lastError,
            };
        }

        var ruleCount = GetPolicy(_settings).RuleCount;
        return new PrivacyShieldStatus
        {
            State = _settings.Enabled ? "Error" : "Disabled",
            Enabled = _settings.Enabled,
            Running = false,
            Port = _settings.Port,
            BindAddress = "not listening",
            Upstream = string.IsNullOrWhiteSpace(_settings.UpstreamDns)
                ? (_settings.EncryptDnsViaDoh ? "encrypted DoH (1.1.1.1, 9.9.9.9)" : "system DNS")
                : _settings.UpstreamDns,
            Queries = 0,
            Allowed = 0,
            Blocked = 0,
            Errors = 0,
            RuleCount = ruleCount,
            Settings = _settings,
            Sources = BuildSourceStatuses(),
            BlockedHistory = _blockedHistory.LoadRecent(),
            Detail = _settings.Enabled
                ? "Privacy Shield is enabled but the resolver is not running."
                : "Privacy Shield is disabled. No DNS query is observed or filtered.",
            LastError = _lastError,
        };
    }

    private PrivacyShieldSourceStatus[] BuildSourceStatuses()
    {
        var totals = _sourceTotals;
        return PrivacyShieldSourceCatalog.All
            .Select(source =>
            {
                var total = totals.GetValueOrDefault(source.Id);
                return new PrivacyShieldSourceStatus(
                    source.Id,
                    source.Name,
                    source.License,
                    _settings.EnabledSourceIds.Contains(source.Id, StringComparer.OrdinalIgnoreCase),
                    total.Entries,
                    total.Updated,
                    _sourceErrors.GetValueOrDefault(source.Id));
            })
            .ToArray();
    }

    private static PrivacyShieldSettings Normalize(PrivacyShieldSettings settings)
    {
        var categories = settings.Categories & (PrivacyCategory.Telemetry |
                                                PrivacyCategory.Ads |
                                                PrivacyCategory.Tracking |
                                                PrivacyCategory.Analytics |
                                                PrivacyCategory.Malware |
                                                PrivacyCategory.Custom);

        return settings with
        {
            Port = Math.Clamp(settings.Port, 1, 65535),
            UpstreamDns = settings.UpstreamDns.Trim(),
            Categories = categories,
            AllowedDomains = NormalizeDomains(settings.AllowedDomains),
            BlockedDomains = NormalizeDomains(settings.BlockedDomains),
            EnabledSourceIds = settings.EnabledSourceIds
                .Where(id => PrivacyShieldSourceCatalog.All.Any(source =>
                    string.Equals(source.Id, id, StringComparison.OrdinalIgnoreCase)))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            PreferredAdapterAlias = settings.PreferredAdapterAlias?.Trim() ?? string.Empty,
            AutoUpdateIntervalHours = Math.Clamp(settings.AutoUpdateIntervalHours, 1, 168),
        };
    }

    private static List<string> NormalizeDomains(IReadOnlyList<string> domains)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in domains)
        {
            var normalized = PrivacyShieldPolicy.NormalizeDomain(domain);
            if (normalized is not null && seen.Add(normalized))
            {
                result.Add(normalized);
                if (result.Count >= PrivacyShieldPolicy.MaxSettingsDomains)
                {
                    break;
                }
            }
        }

        return result;
    }
}
