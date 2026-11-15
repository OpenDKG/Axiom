// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
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
/// returns a new ruleset built from all reachable selected sources.
/// </summary>
public sealed class PrivacyShieldSourceUpdater : IDisposable
{
    private const int MaxBytes = 20 * 1024 * 1024;

    private const int MaxDownloadAttempts = 3;

    // Keep room for every selected source so large ad/tracking lists cannot consume the cap before
    // threat-intelligence, phishing, or telemetry feeds are imported.
    private const int SourceReserve = 25_000;

    private readonly HttpClient _http;

    public PrivacyShieldSourceUpdater(HttpClient? httpClient = null)
    {
        _http = httpClient ?? CreateDefaultHttpClient();
        if (_http.DefaultRequestHeaders.UserAgent.Count == 0)
        {
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("Axiom-PrivacyShield/0.1");
        }
    }

    private static HttpClient CreateDefaultHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AutomaticDecompression = DecompressionMethods.All,
            ConnectCallback = ConnectWithAddressFallbackAsync,
        };
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMinutes(3),
        };
    }

    private static async ValueTask<Stream> ConnectWithAddressFallbackAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken)
            .ConfigureAwait(false);
        if (addresses.Length == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        // Prefer IPv4 first on networks where IPv6 routes or local resolvers refuse/reset TLS feeds,
        // while still trying every resolved address if the first family fails.
        var ordered = addresses
            .OrderBy(address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();

        Exception? lastException = null;
        foreach (var address in ordered)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(TimeSpan.FromSeconds(8));
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), connectCts.Token)
                    .ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception exception) when (exception is SocketException or OperationCanceledException &&
                                              !cancellationToken.IsCancellationRequested)
            {
                lastException = exception;
                socket.Dispose();
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw lastException ?? new SocketException((int)SocketError.ConnectionRefused);
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

        // Import threat-intelligence and phishing feeds first so they never lose priority to bulk lists.
        var orderedSources = sources
            .OrderBy(source => (source.Category & (PrivacyCategory.Malware | PrivacyCategory.Phishing)) != 0 ? 0 : 1)
            .ToArray();

        var rules = new List<PrivacyShieldStoredRule>();
        var statuses = new List<PrivacyShieldSourceStatus>();
        var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var succeededCount = 0;
        var failedSources = new List<string>();

        for (var sourceIndex = 0; sourceIndex < orderedSources.Length; sourceIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = orderedSources[sourceIndex];
            var remainingSources = orderedSources.Length - sourceIndex - 1;
            var reserve = Math.Min(
                SourceReserve,
                PrivacyShieldPolicy.MaxRules / Math.Max(2, orderedSources.Length * 2));
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
                failedSources.Add(source.Id);
                continue;
            }

            try
            {
                var domains = await DownloadAndParseAsync(source, cancellationToken).ConfigureAwait(false);
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
                succeededCount++;
            }
            catch (Exception exception) when (exception is
                         HttpRequestException or IOException or InvalidDataException or
                         TaskCanceledException or ArgumentException)
            {
                failedSources.Add(source.Id);
                statuses.Add(new PrivacyShieldSourceStatus(
                    source.Id,
                    source.Name,
                    source.License,
                    Enabled: true,
                    Entries: 0,
                    UpdatedUtc: null,
                    Error: FormatErrorMessage(exception)));
            }
        }

        if (succeededCount == 0)
        {
            return new PrivacyShieldSourceUpdateResult(
                false,
                [],
                statuses,
                "All selected blocklist sources failed; the previous ruleset was kept.");
        }

        var warning = failedSources.Count == 0
            ? null
            : $"Updated from {succeededCount} of {orderedSources.Length} sources; {failedSources.Count} failed ({string.Join(", ", failedSources)}).";

        return new PrivacyShieldSourceUpdateResult(
            true,
            rules,
            statuses,
            warning);
    }

    public void Dispose() => _http.Dispose();

    private async Task<IReadOnlyList<string>> DownloadAndParseAsync(
        PrivacyShieldSourceInfo source,
        CancellationToken cancellationToken)
    {
        var bytes = await DownloadWithRetriesAsync(source.Url, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(source.Sha256))
        {
            var digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
            if (!string.Equals(digest, source.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The source content does not match its pinned SHA-256.");
            }
        }

        var body = Encoding.UTF8.GetString(bytes);
        return PrivacyShieldPolicy.ParseList(body, PrivacyShieldPolicy.MaxRules);
    }

    private async Task<byte[]> DownloadWithRetriesAsync(string url, CancellationToken cancellationToken)
    {
        Exception? lastException = null;
        for (var attempt = 1; attempt <= MaxDownloadAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await DownloadAsync(url, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (IsTransient(exception, cancellationToken) && attempt < MaxDownloadAttempts)
            {
                lastException = exception;
                await Task.Delay(TimeSpan.FromMilliseconds(400 * attempt), cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        if (lastException is not null)
        {
            throw lastException;
        }

        return await DownloadAsync(url, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsTransient(Exception exception, CancellationToken callerToken)
    {
        if (callerToken.IsCancellationRequested)
        {
            return false;
        }

        if (exception is HttpRequestException httpException)
        {
            return httpException.StatusCode is null
                or >= HttpStatusCode.InternalServerError
                or HttpStatusCode.RequestTimeout
                or HttpStatusCode.TooManyRequests;
        }

        return exception is IOException or TaskCanceledException;
    }

    private static string FormatErrorMessage(Exception exception)
    {
        if (exception.InnerException is { Message.Length: > 0 } inner &&
            !exception.Message.Contains(inner.Message, StringComparison.OrdinalIgnoreCase))
        {
            return $"{exception.Message} ({inner.Message})";
        }

        return exception.Message;
    }

    private async Task<byte[]> DownloadAsync(string url, CancellationToken cancellationToken)
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

        return buffer.ToArray();
    }
}
