// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Privacy;
using Netpetra.Infrastructure.Windows.Dns;

namespace Netpetra.Service;

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

    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly Dictionary<string, string> _sourceErrors =
        new(StringComparer.OrdinalIgnoreCase);

    private PrivacyShieldSettings _settings;

    private IReadOnlyList<PrivacyShieldStoredRule> _rules;

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
        _rules = _ruleStore.Load();
    }

    public Task<PrivacyShieldStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(CreateStatus());
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
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

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var normalized = Normalize(requested);
            if (!_store.Save(normalized))
            {
                _lastError = "Could not write the Privacy Shield settings file.";
                return CreateStatus();
            }

            var previous = _settings;
            await StopServerLockedAsync().ConfigureAwait(false);
            _settings = normalized;
            _lastError = null;

            if (normalized.Enabled)
            {
                await StartServerLockedAsync(cancellationToken).ConfigureAwait(false);
                if (_server is null && previous.Enabled)
                {
                    // A failed reconfiguration must not silently leave a resolver user who pointed
                    // Windows at the old instance without a working fallback. Try the old settings.
                    _settings = previous;
                    await StartServerLockedAsync(cancellationToken).ConfigureAwait(false);
                    _lastError = "The new configuration could not start; the previous resolver settings were restored.";
                }
            }

            return CreateStatus();
        }
        finally
        {
            _gate.Release();
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
                    _rules = result.Rules;
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
        _lastError = null;

        IReadOnlyList<System.Net.IPEndPoint> upstreams;
        if (!string.IsNullOrWhiteSpace(_settings.UpstreamDns))
        {
            if (!SystemDnsResolver.TryParseUpstream(_settings.UpstreamDns, out var endpoint) ||
                endpoint is null)
            {
                _lastError = "The configured upstream DNS address is invalid.";
                return;
            }

            upstreams = [endpoint];
        }
        else
        {
            upstreams = SystemDnsResolver.ResolveSystemDns();
        }

        if (upstreams.Count == 0)
        {
            // If the adapter already points at this loopback resolver, system DNS discovery must
            // not leave the machine without an upstream. Keep a conservative public fallback and
            // let the user override it explicitly.
            upstreams =
            [
                new System.Net.IPEndPoint(System.Net.IPAddress.Parse("1.1.1.1"), 53),
                new System.Net.IPEndPoint(System.Net.IPAddress.Parse("9.9.9.9"), 53),
            ];
            _lastError = "No non-loopback Windows DNS server was found; using fallback upstream DNS. " +
                         "Set an explicit upstream address if this network requires a local resolver.";
        }

        try
        {
            var policy = PrivacyShieldPolicy.Create(_settings, _rules);
            _server = new DnsProxyServer(
                policy,
                upstreams,
                _settings.Port,
                _blockedHistory.Append);
        }
        catch (Exception exception) when (exception is
                     System.Net.Sockets.SocketException or ArgumentException or InvalidOperationException)
        {
            _lastError = exception.Message;
            _server = null;
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

        var ruleCount = PrivacyShieldPolicy.Create(_settings, _rules).RuleCount;
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

    private PrivacyShieldSourceStatus[] BuildSourceStatuses() =>
        PrivacyShieldSourceCatalog.All
            .Select(source =>
            {
                var rules = _rules.Where(rule =>
                    string.Equals(rule.SourceId, source.Id, StringComparison.OrdinalIgnoreCase)).ToArray();
                DateTimeOffset? updated = rules.Length == 0
                    ? null
                    : rules.Max(rule => rule.UpdatedUtc);
                return new PrivacyShieldSourceStatus(
                    source.Id,
                    source.Name,
                    source.License,
                    _settings.EnabledSourceIds.Contains(source.Id, StringComparer.OrdinalIgnoreCase),
                    rules.Length,
                    updated,
                    _sourceErrors.GetValueOrDefault(source.Id));
            })
            .ToArray();

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
