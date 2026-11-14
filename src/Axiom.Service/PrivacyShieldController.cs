// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Runtime;
using Axiom.Contracts.Privacy;
using Axiom.Infrastructure.Windows.Dns;

namespace Axiom.Service;

/// <summary>
/// Owns the opt-in loopback DNS resolver. It never changes adapter DNS settings; a user who wants
/// system-wide filtering must point Windows at the displayed loopback resolver explicitly.
/// </summary>
public sealed class PrivacyShieldController : IAsyncDisposable
{
    private readonly PrivacyShieldSettingsStore _store;

    private readonly PrivacyShieldRuleStore _ruleStore;

    private readonly PrivacyShieldSourceUpdater _sourceUpdater;

    private readonly PrivacyShieldBlockedHistoryStore _blockedHistory = new();

    /// <summary>Writes buffered blocked history before the service stops.</summary>
    public void FlushBlockedHistory() => _blockedHistory.Flush();

    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly object _rulesGate = new();

    private readonly Dictionary<string, string> _sourceErrors =
        new(StringComparer.OrdinalIgnoreCase);

    private PrivacyShieldSettings _settings;

    private IReadOnlyList<PrivacyShieldStoredRule> _rules = [];

    private IReadOnlyDictionary<string, (int Entries, DateTimeOffset? Updated)> _sourceTotals =
        new Dictionary<string, (int, DateTimeOffset?)>(StringComparer.OrdinalIgnoreCase);

    private Task<IReadOnlyList<PrivacyShieldStoredRule>>? _rulesTask;

    private PrivacyShieldPolicy? _policy;

    private PrivacyShieldSettings? _policySettings;

    private IReadOnlyList<PrivacyShieldStoredRule>? _policyRules;

    private DnsProxyServer? _server;

    private string? _lastError;

    public PrivacyShieldController(
        PrivacyShieldSettingsStore store,
        PrivacyShieldRuleStore? ruleStore = null,
        PrivacyShieldSourceUpdater? sourceUpdater = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _ruleStore = ruleStore ?? new PrivacyShieldRuleStore();
        _sourceUpdater = sourceUpdater ?? new PrivacyShieldSourceUpdater();
        _settings = store.Load();
    }

    /// <summary>Whether the persisted configuration asks the resolver to run.</summary>
    public bool IsEnabled => _settings.Enabled;

    /// <summary>Whether the loopback resolver is listening right now.</summary>
    public bool IsResolverRunning => Volatile.Read(ref _server) is not null;

    public async Task<PrivacyShieldStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SetRules(await EnsureRulesLoadedAsync().ConfigureAwait(false));
        return CreateStatus();
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_settings.Enabled)
        {
            SetRules(await EnsureRulesLoadedAsync().ConfigureAwait(false));
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

        SetRules(await EnsureRulesLoadedAsync().ConfigureAwait(false));

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
                _ = Task.Run(PrivacyDnsFailSafe.RestoreIfNeeded);
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
            _lastError = startWarning;
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
        _lastError = warning;
        return Task.FromResult(true);
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
                    _lastError = null;
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
            _lastError = warning;
            return;
        }

        _server = null;
        _lastError = error;

        // A failed start (port taken, socket error) must not leave the adapter without a resolver.
        _ = Task.Run(PrivacyDnsFailSafe.RestoreIfNeeded);
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
            if (!SystemDnsResolver.TryParseUpstreamTarget(settings.UpstreamDns, out var target) ||
                target is null)
            {
                error = "The configured upstream DNS address or DoH URL is invalid.";
                return false;
            }

            targets = [target];
        }
        else
        {
            targets = SystemDnsResolver.UpgradeEndpoints(SystemDnsResolver.ResolveSystemDns());
        }

        if (targets.Count == 0)
        {
            // If the adapter already points at this loopback resolver, system DNS discovery must
            // not leave the machine without an upstream. Keep encrypted public DoH fallbacks and
            // let the user override them explicitly.
            targets = SystemDnsResolver.UpgradeEndpoints(
            [
                new System.Net.IPEndPoint(System.Net.IPAddress.Parse("1.1.1.1"), 53),
                new System.Net.IPEndPoint(System.Net.IPAddress.Parse("8.8.8.8"), 53),
            ]);
            warning = "No non-loopback Windows DNS server was found; using encrypted DoH fallback upstream DNS. " +
                      "Set an explicit upstream address if this network requires a local resolver.";
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
                });
            return true;
        }
        catch (Exception exception) when (exception is
                     System.Net.Sockets.SocketException or ArgumentException or InvalidOperationException)
        {
            error = exception.Message;
            return false;
        }
    }

    private async Task StopServerLockedAsync()
    {
        if (_server is null)
        {
            return;
        }

        await _server.DisposeAsync().ConfigureAwait(false);
        _server = null;
    }

    private Task<IReadOnlyList<PrivacyShieldStoredRule>> EnsureRulesLoadedAsync()
    {
        lock (_rulesGate)
        {
            // The 43 MB compiled ruleset is loaded off the service-startup thread so the pipe,
            // firewall consent and monitor are available before optional filtering is ready.
            return _rulesTask ??= Task.Run(() =>
            {
                var rules = _ruleStore.Load();

                // Parsing the ruleset leaves large temporary buffers on the large object heap.
                // Compact once here so that space is returned instead of staying reserved for the
                // whole service lifetime; a single startup pass costs far less than the retention.
                GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
                return rules;
            });
        }
    }

    /// <summary>
    /// Adopts a loaded ruleset once. Re-assigning the same instance is a no-op so a status poll
    /// does not rebuild the per-source index.
    /// </summary>
    private void SetRules(IReadOnlyList<PrivacyShieldStoredRule> rules)
    {
        if (ReferenceEquals(_rules, rules))
        {
            return;
        }

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
        _rules = rules;
    }

    /// <summary>
    /// Builds the compiled policy at most once per (settings, ruleset) pair. The policy holds an
    /// index of every blocked domain, so rebuilding it for a status poll costs hundreds of MB.
    /// </summary>
    private PrivacyShieldPolicy GetPolicy(PrivacyShieldSettings settings)
    {
        var policy = _policy;
        if (policy is not null &&
            ReferenceEquals(_policySettings, settings) &&
            ReferenceEquals(_policyRules, _rules))
        {
            return policy;
        }

        policy = PrivacyShieldPolicy.Create(settings, _rules);
        _policy = policy;
        _policySettings = settings;
        _policyRules = _rules;
        return policy;
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
                ? "system DNS"
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
