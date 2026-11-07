// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Axiom.Contracts.Ai;
using Axiom.Contracts.History;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Reputation;
using Axiom.Infrastructure.Linux;

namespace Axiom.Desktop.Linux;

/// <summary>
/// Linux desktop host. The service keeps the privileged boundary; this process is an unprivileged
/// IPC client that serves a loopback-only browser UI. No remote listener, no shell, no generic proxy.
/// </summary>
public static class Program
{
    private const string TokenHeader = "X-Axiom-Token";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static async Task<int> Main(string[] args)
    {
        var options = UiOptions.Parse(args);

        if (options.SelfCheck)
        {
            return await SelfCheckAsync(options).ConfigureAwait(false);
        }

        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });

        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(options => options.SingleLine = true);

        foreach (var endpoint in builder.Configuration.GetSection("Kestrel:Endpoints").GetChildren())
        {
            if (!IsLoopbackEndpoint(endpoint["Url"]))
            {
                Console.Error.WriteLine(
                    "Axiom UI refuses to start: Kestrel is configured with a non-loopback endpoint.");
                return 2;
            }
        }

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(IPAddress.Loopback, options.Port);
            kestrel.AddServerHeader = false;
        });

        var client = new IpcPipeClient(
            IpcPipe.Name,
            unixSocketPath: options.SocketPath);
        var credentials = new LinuxSecretServiceCredentialStore();
        var aiSettings = new LinuxAiAnalystSettings();
        using var aiClient = new AiAnalystClient();
        using var reputationClient = new VirusTotalClient();

        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            if (!IsLoopbackHost(context.Request.Host))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";
            // API responses carry data, so they are never cached. Static assets must revalidate:
            // a browser that kept an old app.js would run the previous release's UI.
            context.Response.Headers.CacheControl =
                context.Request.Path.StartsWithSegments("/api") ? "no-store" : "no-cache";

            await next().ConfigureAwait(false);
        });

        app.UseDefaultFiles();
        app.UseStaticFiles();

        app.MapGet("/api/status", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, async () =>
        {
            var health = await client.SendAsync<ServiceHealth>(
                IpcCommandTypes.ServiceHealth, null, context.RequestAborted).ConfigureAwait(false);
            var capabilities = await client.SendAsync<ServiceCapabilities>(
                IpcCommandTypes.Capabilities, null, context.RequestAborted).ConfigureAwait(false);

            return new
            {
                health,
                capabilities,
                endpoint = IpcEndpoint.UsesUnixSocket
                    ? IpcEndpoint.ResolveClientUnixSocketPath()
                    : IpcPipe.Name,
            };
        })));

        app.MapGet("/api/connections", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, async () =>
        {
            var snapshot = await client.SendAsync<Contracts.Monitoring.ConnectionSnapshot>(
                IpcCommandTypes.Snapshot, null, context.RequestAborted).ConfigureAwait(false);
            return snapshot;
        })));

        app.MapGet("/api/history", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, async () =>
        {
            var hours = Clamp(QueryInt(context, "hours", 24), 1, 24 * 30);
            var limit = Clamp(QueryInt(context, "limit", 200), 1, 500);
            var offset = Math.Max(QueryInt(context, "offset", 0), 0);
            var search = context.Request.Query["search"].ToString();

            var query = new HistoryQuery
            {
                FromUtc = DateTimeOffset.UtcNow.AddHours(-hours),
                ToUtc = DateTimeOffset.UtcNow,
                Search = string.IsNullOrWhiteSpace(search) ? null : search.Trim(),
                Limit = limit,
                Offset = offset,
            };

            return await client.SendAsync<HistoryPage>(
                IpcCommandTypes.HistoryQuery, query, context.RequestAborted).ConfigureAwait(false);
        })));

        app.MapGet("/api/autostart", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, () =>
            Task.FromResult<object>(new { enabled = LinuxAutostart.IsEnabled(), supported = AutostartExecutable() is not null }))));

        app.MapPost("/api/autostart", (Func<HttpContext, Task<IResult>>)(context =>
            GuardedJson(context, token, async () =>
            {
                var body = await ReadJsonAsync<AutostartRequest>(context).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("An autostart request is required.");

                if (body.Enabled)
                {
                    var executable = AutostartExecutable()
                        ?? throw new InvalidOperationException(
                            "Autostart needs the installed desktop executable; run the published " +
                            "Axiom.Desktop.Linux binary, not a development host.");
                    LinuxAutostart.Enable(executable);
                }
                else
                {
                    LinuxAutostart.Disable();
                }

                return new { enabled = LinuxAutostart.IsEnabled() };
            })));

        app.MapGet("/api/ai", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, async () =>
        {
            var settings = aiSettings.Load();
            var key = await credentials.GetAsync("ai-analyst", context.RequestAborted).ConfigureAwait(false);
            return new
            {
                settings,
                credential = new
                {
                    backend = credentials.Backend,
                    available = credentials.IsAvailable,
                    hasKey = !string.IsNullOrEmpty(key),
                },
            };
        })));

        app.MapPost("/api/ai/settings", (Func<HttpContext, Task<IResult>>)(context =>
            GuardedJson(context, token, async () =>
            {
                var settings = await ReadJsonAsync<AiAnalystSettings>(context).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("A settings object is required.");
                if ((settings.Enabled || !string.IsNullOrWhiteSpace(settings.Endpoint)) &&
                    !IsAllowedAiEndpoint(settings.Endpoint))
                {
                    throw new InvalidOperationException(
                        "The endpoint must be HTTPS, or HTTP on a loopback address for a local model.");
                }

                aiSettings.Save(settings);
                return new { saved = true };
            })));

        app.MapPost("/api/ai/key", (Func<HttpContext, Task<IResult>>)(context =>
            GuardedJson(context, token, async () =>
            {
                var body = await ReadJsonAsync<KeyRequest>(context).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(body?.Key) || body.Key.Length > 4096)
                {
                    throw new InvalidOperationException("A key is required.");
                }

                await credentials.SetAsync("ai-analyst", body.Key, context.RequestAborted).ConfigureAwait(false);
                return new { stored = true };
            })));

        app.MapDelete("/api/ai/key", (Func<HttpContext, Task<IResult>>)(context => GuardedJson(context, token, async () =>
        {
            await credentials.DeleteAsync("ai-analyst", context.RequestAborted).ConfigureAwait(false);
            return new { deleted = true };
        })));

        app.MapPost("/api/ai/analyze", (Func<HttpContext, Task<IResult>>)(context =>
            GuardedJson(context, token, async () =>
            {
                var settings = aiSettings.Load();
                if (!settings.Enabled)
                {
                    throw new InvalidOperationException("The AI analyst is disabled.");
                }

                var key = await credentials.GetAsync("ai-analyst", context.RequestAborted).ConfigureAwait(false);
                if (string.IsNullOrEmpty(key))
                {
                    throw new InvalidOperationException(
                        "No provider key is stored in Secret Service; store one before analyzing.");
                }

                var snapshot = await client.SendAsync<Contracts.Monitoring.ConnectionSnapshot>(
                    IpcCommandTypes.Snapshot, null, context.RequestAborted).ConfigureAwait(false);
                var evidence = AiEvidenceBuilder.Build(
                    snapshot.Connections,
                    snapshot.SourceName,
                    snapshot.Limitations,
                    settings.MaxConnections,
                    settings.RedactPaths);

                return await aiClient.AnalyzeAsync(settings, key, evidence, context.RequestAborted)
                    .ConfigureAwait(false);
            })));

        app.MapGet("/api/reputation", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, async () =>
        {
            var stored = await credentials.GetAsync("virustotal", context.RequestAborted).ConfigureAwait(false);
            return new
            {
                credential = new
                {
                    backend = credentials.Backend,
                    available = credentials.IsAvailable,
                    hasKey = !string.IsNullOrEmpty(stored),
                },
            };
        })));

        app.MapPost("/api/reputation/key", (Func<HttpContext, Task<IResult>>)(context =>
            GuardedJson(context, token, async () =>
            {
                var body = await ReadJsonAsync<KeyRequest>(context).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(body?.Key) || body.Key.Length > 4096)
                {
                    throw new InvalidOperationException("A key is required.");
                }

                await credentials.SetAsync("virustotal", body.Key, context.RequestAborted).ConfigureAwait(false);
                return new { stored = true };
            })));

        app.MapDelete("/api/reputation/key", (Func<HttpContext, Task<IResult>>)(context => GuardedJson(context, token, async () =>
        {
            await credentials.DeleteAsync("virustotal", context.RequestAborted).ConfigureAwait(false);
            return new { deleted = true };
        })));

        app.MapPost("/api/reputation", (Func<HttpContext, Task<IResult>>)(context =>
            GuardedJson(context, token, async () =>
            {
                var body = await ReadJsonAsync<ReputationRequest>(context).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(body?.Path) || !Path.IsPathFullyQualified(body.Path) ||
                    !File.Exists(body.Path))
                {
                    throw new InvalidOperationException("An absolute path to an existing file is required.");
                }

                var key = await credentials.GetAsync("virustotal", context.RequestAborted).ConfigureAwait(false);
                if (string.IsNullOrEmpty(key))
                {
                    throw new InvalidOperationException(credentials.IsAvailable
                        ? "No VirusTotal key is stored in Secret Service; only the SHA-256 is sent."
                        : "No Secret Service keyring is available, so a VirusTotal key cannot be stored on this host.");
                }

                var hash = await Sha256Async(body.Path, context.RequestAborted).ConfigureAwait(false);
                var report = await reputationClient.LookupHashAsync(hash, key, context.RequestAborted)
                    .ConfigureAwait(false);
                return new { sha256 = hash, report };
            })));

        app.MapGet("/api/history.csv", (Func<HttpContext, Task<IResult>>)(context =>
            HistoryCsvAsync(context, token, client)));

        app.MapGet("/api/firewall", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, async () =>
            await client.SendAsync<Contracts.Ipc.FirewallRulesSnapshot>(
                IpcCommandTypes.RulesQuery, null, context.RequestAborted).ConfigureAwait(false))));

        app.MapGet("/api/privacy", (Func<HttpContext, Task<IResult>>)(context => Guarded(context, token, async () =>
            await client.SendAsync<Contracts.Privacy.PrivacyShieldStatus>(
                IpcCommandTypes.PrivacyStatus, null, context.RequestAborted).ConfigureAwait(false))));

        app.MapFallback("/api/{**path}", () => Results.NotFound());
        app.MapFallbackToFile("index.html");

        await app.StartAsync().ConfigureAwait(false);

        var addresses = app.Services
            .GetRequiredService<IServer>()
            .Features
            .Get<IServerAddressesFeature>()!
            .Addresses
            .ToArray();

        if (addresses.Length == 0 || addresses.Any(candidate => !IsLoopbackEndpoint(candidate)))
        {
            Console.Error.WriteLine("Axiom UI refuses to serve: a non-loopback listener was bound.");
            await app.StopAsync().ConfigureAwait(false);
            return 2;
        }

        var address = addresses[0];
        var launchUrl = $"{address}/#t={token}";
        Console.WriteLine($"Axiom UI: {launchUrl}");

        if (options.OpenBrowser && !options.NoBrowser)
        {
            TryOpenBrowser(launchUrl);
        }

        await app.WaitForShutdownAsync().ConfigureAwait(false);
        return 0;
    }

    private static async Task<IResult> GuardedJson(
        HttpContext context,
        string token,
        Func<Task<object>> action)
    {
        if (!TokenMatches(context, token))
        {
            return Results.Json(new { error = "unauthorized" }, JsonOptions, statusCode: StatusCodes.Status401Unauthorized);
        }

        try
        {
            return Results.Json(await action().ConfigureAwait(false), JsonOptions);
        }
        catch (NotSupportedException exception)
        {
            return Results.Json(new { error = "credential-unavailable", message = exception.Message }, JsonOptions,
                statusCode: StatusCodes.Status409Conflict);
        }
        catch (JsonException)
        {
            return Results.Json(new { error = "invalid-request", message = "A valid JSON request body is required." }, JsonOptions,
                statusCode: StatusCodes.Status400BadRequest);
        }
        catch (InvalidOperationException exception)
        {
            return Results.Json(new { error = "invalid-request", message = exception.Message }, JsonOptions,
                statusCode: StatusCodes.Status400BadRequest);
        }
        catch (IpcClientException exception)
        {
            return Results.Json(new { error = exception.Code, message = exception.Message }, JsonOptions,
                statusCode: StatusCodes.Status502BadGateway);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or TimeoutException or IOException or UnauthorizedAccessException)
        {
            return Results.Json(new { error = "upstream-unavailable", message = exception.Message }, JsonOptions,
                statusCode: StatusCodes.Status502BadGateway);
        }
    }

    private static async Task<T?> ReadJsonAsync<T>(HttpContext context)
    {
        const int maxBytes = 32 * 1024;
        if (context.Request.ContentLength is > maxBytes)
        {
            throw new InvalidOperationException("Request body is too large.");
        }

        // Chunked requests have no Content-Length; enforce the cap while reading instead.
        await using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var read = await context.Request.Body.ReadAsync(chunk, context.RequestAborted).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > maxBytes)
            {
                throw new InvalidOperationException("Request body is too large.");
            }

            buffer.Write(chunk, 0, read);
        }

        if (buffer.Length == 0)
        {
            return default;
        }

        return JsonSerializer.Deserialize<T>(buffer.ToArray(), JsonOptions);
    }

    private static string? AutostartExecutable()
    {
        var path = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        var name = Path.GetFileName(path);
        return name.StartsWith("Axiom.Desktop.Linux", StringComparison.Ordinal) ? path : null;
    }

    private static bool IsAllowedAiEndpoint(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return true;
        }

        return uri.Scheme == Uri.UriSchemeHttp && IPAddress.TryParse(uri.Host, out var address) && IPAddress.IsLoopback(address);
    }

    private static async Task<string> Sha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }

    private static async Task<IResult> HistoryCsvAsync(HttpContext context, string token, IpcPipeClient client)
    {
        if (!TokenMatches(context, token))
        {
            return Results.Json(new { error = "unauthorized" }, JsonOptions, statusCode: StatusCodes.Status401Unauthorized);
        }

        var hours = Clamp(QueryInt(context, "hours", 24), 1, 24 * 30);
        var search = context.Request.Query["search"].ToString();
        var query = new HistoryQuery
        {
            FromUtc = DateTimeOffset.UtcNow.AddHours(-hours),
            ToUtc = DateTimeOffset.UtcNow,
            Search = string.IsNullOrWhiteSpace(search) ? null : search.Trim(),
        };

        try
        {
            var rows = new List<Contracts.History.HistoryRow>();
            for (var page = 0; page < 20; page++)
            {
                query = query with { Limit = 5000, Offset = page * 5000 };
                var result = await client.SendAsync<HistoryPage>(
                    IpcCommandTypes.HistoryQuery, query, context.RequestAborted).ConfigureAwait(false);
                rows.AddRange(result.Rows);
                if (result.Rows.Count < 5000)
                {
                    break;
                }
            }

            var csv = HistoryCsv.Format(rows);
            var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv)).ToArray();
            return Results.File(
                bytes,
                "text/csv; charset=utf-8",
                $"axiom-history-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.csv");
        }
        catch (IpcClientException exception)
        {
            var status = exception.Code == IpcErrorCodes.ServiceUnavailable
                ? StatusCodes.Status503ServiceUnavailable
                : StatusCodes.Status502BadGateway;
            return Results.Json(new { error = exception.Code, message = exception.Message }, JsonOptions, statusCode: status);
        }
    }

    private static bool IsLoopbackHost(HostString host)
    {
        var hostName = host.Host;
        return string.Equals(hostName, "127.0.0.1", StringComparison.Ordinal) ||
               string.Equals(hostName, "localhost", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(hostName, "[::1]", StringComparison.Ordinal) ||
               string.Equals(hostName, "::1", StringComparison.Ordinal);
    }

    private static async Task<IResult> Guarded(HttpContext context, string token, Func<Task<object>> action)
    {
        if (!TokenMatches(context, token))
        {
            return Results.Json(new { error = "unauthorized" }, JsonOptions, statusCode: StatusCodes.Status401Unauthorized);
        }

        try
        {
            return Results.Json(await action().ConfigureAwait(false), JsonOptions);
        }
        catch (IpcClientException exception)
        {
            var status = exception.Code == IpcErrorCodes.ServiceUnavailable
                ? StatusCodes.Status503ServiceUnavailable
                : StatusCodes.Status502BadGateway;
            return Results.Json(new { error = exception.Code, message = exception.Message }, JsonOptions, statusCode: status);
        }
        catch (NotSupportedException exception)
        {
            // Credential-store backend missing (no keyring/session bus): not a server fault.
            return Results.Json(new { error = "credential-unavailable", message = exception.Message }, JsonOptions,
                statusCode: StatusCodes.Status409Conflict);
        }
        catch (TimeoutException exception)
        {
            // A stalled credential backend must not surface as an unhandled 500.
            return Results.Json(new { error = "credential-unavailable", message = exception.Message }, JsonOptions,
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }

    /// <summary>
    /// The UI is loopback-only by contract; a configuration-supplied endpoint must not widen it.
    /// </summary>
    private static bool IsLoopbackEndpoint(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               (IPAddress.TryParse(uri.Host, out var address) && IPAddress.IsLoopback(address));
    }

    private static bool TokenMatches(HttpContext context, string token)
    {
        var supplied = context.Request.Headers[TokenHeader].ToString();
        if (supplied.Length == 0)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(supplied),
            Encoding.UTF8.GetBytes(token));
    }

    private static int QueryInt(HttpContext context, string name, int fallback) =>
        int.TryParse(context.Request.Query[name].ToString(), out var value) ? value : fallback;

    private static int Clamp(int value, int min, int max) => Math.Clamp(value, min, max);

    private static void TryOpenBrowser(string url)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DISPLAY")) &&
                string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY")))
            {
                return;
            }

            using var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "xdg-open",
                    ArgumentList = { url },
                    UseShellExecute = false,
                },
            };
            process.Start();
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // Headless sessions keep the URL on stdout.
        }
    }

    /// <summary>Used by the installer and the test harness: verifies the host and the service are usable.</summary>
    private static async Task<int> SelfCheckAsync(UiOptions options)
    {
        var client = new IpcPipeClient(IpcPipe.Name, unixSocketPath: options.SocketPath);
        try
        {
            var health = await client.SendAsync<ServiceHealth>(
                IpcCommandTypes.ServiceHealth, null, CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine($"service={health.Status} source={health.SourceName} connections={health.ConnectionCount}");
            return 0;
        }
        catch (IpcClientException exception)
        {
            Console.Error.WriteLine($"service unavailable: {exception.Code}: {exception.Message}");
            return 2;
        }
    }
}

internal sealed record KeyRequest(string? Key);

internal sealed record ReputationRequest(string? Path);

internal sealed record AutostartRequest(bool Enabled);

public sealed record UiOptions(int Port, bool NoBrowser, bool OpenBrowser, bool SelfCheck, string? SocketPath)
{
    public static UiOptions Parse(string[] args)
    {
        var port = 0;
        var noBrowser = false;
        var selfCheck = false;
        string? socket = null;

        for (var index = 0; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--port" when index + 1 < args.Length &&
                                   int.TryParse(args[index + 1], out var parsedPort):
                    port = parsedPort;
                    index++;
                    break;

                case "--no-browser":
                    noBrowser = true;
                    break;

                case "--self-check":
                    selfCheck = true;
                    break;

                case "--socket" when index + 1 < args.Length:
                    socket = args[index + 1];
                    index++;
                    break;

                case "--help":
                case "-h":
                    Console.WriteLine("""
                        Axiom.Desktop.Linux [--port N] [--no-browser] [--socket PATH] [--self-check]

                        Serves the local Axiom UI on 127.0.0.1. The UI talks to Axiom.Service
                        over its local socket; no remote listener is opened.
                        """);
                    Environment.Exit(0);
                    break;
            }
        }

        return new UiOptions(port, noBrowser, !noBrowser, selfCheck, socket);
    }
}
