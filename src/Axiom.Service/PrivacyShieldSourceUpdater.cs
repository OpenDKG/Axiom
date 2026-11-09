// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Http;
using System.Text;
using Axiom.Contracts.Privacy;

namespace Axiom.Service;

public sealed record PrivacyShieldSourceUpdateResult(
    bool Success,
    IReadOnlyList<PrivacyShieldStoredRule> Rules,
    IReadOnlyList<PrivacyShieldSourceStatus> Sources,
    string? Error);

/// <summary>
/// Downloads only catalogued HTTPS lists, applies hard size/entry limits, normalizes domains and
/// returns a complete new ruleset. The caller atomically swaps it only when every selected source
/// succeeded.
/// </summary>
public sealed class PrivacyShieldSourceUpdater : IDisposable
{
    private const int MaxBytes = 20 * 1024 * 1024;

    // Keep room for every selected source so a large list cannot consume the whole cap before a
    // smaller telemetry list such as WindowsSpyBlocker is imported.
    private const int SourceReserve = 10_000;

    private readonly HttpClient _http;

    public PrivacyShieldSourceUpdater(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(45),
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("Axiom-PrivacyShield/0.1");
    }

    public async Task<PrivacyShieldSourceUpdateResult> UpdateAsync(
        IReadOnlyList<PrivacyShieldSourceInfo> sources,
        CancellationToken cancellationToken)
    {
        if (sources.Count == 0)
        {
            return new PrivacyShieldSourceUpdateResult(
                false,
                [],
                [],
                "Select at least one catalogued source before updating.");
        }

        var rules = new List<PrivacyShieldStoredRule>();
        var statuses = new List<PrivacyShieldSourceStatus>();
        var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var success = true;

        for (var sourceIndex = 0; sourceIndex < sources.Count; sourceIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = sources[sourceIndex];
            var remainingSources = sources.Count - sourceIndex - 1;
            var reserve = Math.Min(
                SourceReserve,
                PrivacyShieldPolicy.MaxRules / Math.Max(2, sources.Count * 2));
            var sourceLimit = Math.Max(
                1,
                PrivacyShieldPolicy.MaxRules - (remainingSources * reserve));

            if (rules.Count >= sourceLimit)
            {
                statuses.Add(new PrivacyShieldSourceStatus(
                    source.Id,
                    source.Name,
                    source.License,
                    Enabled: true,
                    Entries: 0,
                    UpdatedUtc: null,
                    Error: "The combined ruleset reached the local rule limit."));
                success = false;
                continue;
            }

            try
            {
                var body = await DownloadAsync(source.Url, cancellationToken).ConfigureAwait(false);
                var domains = PrivacyShieldPolicy.ParseList(body, PrivacyShieldPolicy.MaxRules);
                if (domains.Count == 0)
                {
                    throw new InvalidDataException("The source contained no valid domains.");
                }

                var added = 0;
                var upgraded = 0;
                var now = DateTimeOffset.UtcNow;
                foreach (var domain in domains)
                {
                    if (rules.Count >= sourceLimit)
                    {
                        break;
                    }

                    if (index.TryGetValue(domain, out var existingIndex))
                    {
                        // A malware source upgrades a duplicate already listed as an ad or tracker,
                        // so a blocked malware domain is never categorised as advertising. The first
                        // source keeps the attribution; the category only grows.
                        var existing = rules[existingIndex];
                        var merged = existing.Category | source.Category;
                        if (merged != existing.Category)
                        {
                            rules[existingIndex] = existing with { Category = merged };
                            upgraded++;
                        }

                        continue;
                    }

                    index[domain] = rules.Count;
                    rules.Add(new PrivacyShieldStoredRule(domain, source.Id, source.Category, now));
                    added++;
                }

                statuses.Add(new PrivacyShieldSourceStatus(
                    source.Id,
                    source.Name,
                    source.License,
                    Enabled: true,
                    Entries: added + upgraded,
                    UpdatedUtc: now,
                    Error: null));
            }
            catch (Exception exception) when (exception is
                         HttpRequestException or IOException or InvalidDataException or
                         TaskCanceledException or ArgumentException)
            {
                success = false;
                statuses.Add(new PrivacyShieldSourceStatus(
                    source.Id,
                    source.Name,
                    source.License,
                    Enabled: true,
                    Entries: 0,
                    UpdatedUtc: null,
                    Error: exception.Message));
            }
        }

        return new PrivacyShieldSourceUpdateResult(
            success,
            rules,
            statuses,
            success ? null : "One or more sources failed; the previous ruleset was kept.");
    }

    public void Dispose() => _http.Dispose();

    private async Task<string> DownloadAsync(string url, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Blocklist sources must use HTTPS.");
        }

        using var response = await _http
            .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxBytes)
            {
                throw new InvalidDataException("The blocklist exceeded the 20 MB import limit.");
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
