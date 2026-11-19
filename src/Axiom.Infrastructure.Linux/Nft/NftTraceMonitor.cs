// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>A line source for <c>nft monitor trace</c>; faked in tests.</summary>
public interface INftTraceSource
{
    IAsyncEnumerable<string> ReadLinesAsync(CancellationToken ct);
}

/// <summary>Runs <c>nft monitor trace</c> as a long-lived child and streams its stdout lines.</summary>
[SupportedOSPlatform("linux")]
public sealed class NftTraceProcessSource : INftTraceSource
{
    private readonly string _binary;

    public NftTraceProcessSource(string? binary = null)
    {
        _binary = string.IsNullOrWhiteSpace(binary) ? NftProcessRunner.DefaultBinary : binary;
    }

    public async IAsyncEnumerable<string> ReadLinesAsync([EnumeratorCancellation] CancellationToken ct)
    {
        var start = new ProcessStartInfo(_binary)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.Environment.Remove("NOTIFY_SOCKET"); // keep systemd's notify channel to the main pid
        start.ArgumentList.Add("monitor");
        start.ArgumentList.Add("trace");
        using var process = new Process { StartInfo = start };
        process.Start();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var line = await process.StandardOutput.ReadLineAsync(ct).ConfigureAwait(false);
                if (line is null)
                {
                    yield break;
                }

                yield return line;
            }
        }
        finally
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                }
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Already gone.
            }
        }
    }
}

/// <summary>
/// Turns trace records into <c>flow.open</c>/<c>flow.close</c> NDJSON events (verdict <c>block</c>,
/// ruleId from the rule comment). The pid is attributed through <see cref="ISocketOwnerLookup"/>
/// (local port → inode → pid); when that fails, the first process of the rule's app cgroup is used
/// with the app path, so every blocked attempt is at least attributed to the right application.
/// </summary>
public sealed class NftTraceMonitor
{
    private readonly INftTraceSource _source;
    private readonly ISocketOwnerLookup _sockets;
    private readonly Func<Guid, (int Pid, string? Path)?> _fallback;
    private readonly IFilterEventSink _sink;
    private readonly TimeProvider _time;
    private long _events;

    public NftTraceMonitor(
        INftTraceSource source,
        ISocketOwnerLookup sockets,
        Func<Guid, (int Pid, string? Path)?> fallback,
        IFilterEventSink sink,
        TimeProvider time)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _sockets = sockets ?? throw new ArgumentNullException(nameof(sockets));
        _fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public long EventsEmitted => Interlocked.Read(ref _events);

    public async Task RunAsync(CancellationToken ct)
    {
        var parser = new NftTraceParser();
        await foreach (var line in _source.ReadLinesAsync(ct).ConfigureAwait(false))
        {
            if (parser.Feed(line) is { } trace)
            {
                Publish(trace);
            }
        }
    }

    /// <summary>Emits the event pair for one completed trace (pure apart from the lookups; used by tests).</summary>
    public void Publish(NftTraceEvent trace)
    {
        ArgumentNullException.ThrowIfNull(trace);
        var owner = _sockets.FindOwner(trace.Protocol, trace.LocalAddress, trace.LocalPort);
        var pid = owner?.Pid ?? -1;
        var path = owner?.ExePath;
        if (owner is null && trace.RuleId is { } ruleId && _fallback(ruleId) is { } app)
        {
            pid = app.Pid;
            path = app.Path;
        }

        var now = _time.GetUtcNow();
        var id = string.Create(CultureInfo.InvariantCulture, $"nft-{trace.TraceId}-{Interlocked.Increment(ref _events)}");
        _sink.Emit(FilterEventFormatter.FlowOpen(id, trace, pid, path, now));
        _sink.Emit(FilterEventFormatter.FlowClose(id, now));
    }
}
