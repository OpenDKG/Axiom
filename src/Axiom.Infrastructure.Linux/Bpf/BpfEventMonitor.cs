// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Text.Json;
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Bpf;

/// <summary>A line source for the <c>axiom-bpf-events</c> helper; faked in tests.</summary>
public interface IBpfEventSource
{
    IAsyncEnumerable<string> ReadLinesAsync(CancellationToken ct);
}

/// <summary>Runs the shipped helper as a long-lived child and streams its NDJSON stdout (the <c>nft monitor trace</c> pattern).</summary>
[SupportedOSPlatform("linux")]
public sealed class BpfEventProcessSource : IBpfEventSource
{
    private readonly string _helper;
    private readonly string _mapPin;

    public BpfEventProcessSource(string helper, string mapPin)
    {
        _helper = helper ?? throw new ArgumentNullException(nameof(helper));
        _mapPin = mapPin ?? throw new ArgumentNullException(nameof(mapPin));
    }

    public async IAsyncEnumerable<string> ReadLinesAsync([EnumeratorCancellation] CancellationToken ct)
    {
        var start = new ProcessStartInfo(_helper)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.Environment.Remove("NOTIFY_SOCKET");
        start.ArgumentList.Add(_mapPin);
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

/// <summary>One record printed by the helper (see <c>axiom-bpf-events.c</c>).</summary>
public sealed record BpfFlowEvent(
    int Pid,
    ulong CgroupId,
    uint DevMajor,
    uint DevMinor,
    ulong Ino,
    int Family,
    int Protocol,
    string RemoteAddress,
    int RemotePort,
    string Verdict,
    string Source,
    string Hook,
    long Generation,
    Guid? RuleId)
{
    public string ProtocolName => Protocol switch { 6 => "tcp", 17 => "udp", _ => "other" };

    public string LocalAddress => Family == 10 ? "::" : "0.0.0.0";
}

/// <summary>Parses helper lines; the <c>hello</c> line and garbage return null.</summary>
public static class BpfEventParser
{
    public static BpfFlowEvent? TryParse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line) || line[0] != '{')
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.TryGetProperty("type", out _) || !root.TryGetProperty("verdict", out var verdict))
            {
                return null;
            }

            if (root.TryGetProperty("abi", out var abi) && abi.TryGetInt32(out var abiValue) && abiValue != BpfLayout.Abi)
            {
                return null;
            }

            return new BpfFlowEvent(
                Int(root, "pid"),
                ULong(root, "cgroup"),
                (uint)ULong(root, "devMajor"),
                (uint)ULong(root, "devMinor"),
                ULong(root, "ino"),
                Int(root, "family"),
                Int(root, "proto"),
                Str(root, "daddr"),
                Int(root, "dport"),
                verdict.GetString() is "block" ? "block" : "allow",
                Str(root, "source"),
                Str(root, "hook"),
                (long)ULong(root, "generation"),
                BpfLayout.ParseRuleId(Str(root, "ruleId")));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static int Int(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.TryGetInt64(out var number) ? (int)Math.Clamp(number, int.MinValue, int.MaxValue) : 0;

    private static ulong ULong(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.TryGetUInt64(out var number) ? number : 0;

    private static string Str(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
}

/// <summary>
/// Turns helper records into the same <c>flow.open</c>/<c>flow.close</c> NDJSON pair the trace
/// monitor emits, with event ids <c>bpf-N</c> so the verdict source is visible downstream. The
/// pid is exact (the hook runs in the caller's context); the path comes from
/// <c>/proc/pid/exe</c> while the process lives, else from the rule's app path.
/// </summary>
public sealed class BpfEventMonitor
{
    private readonly IBpfEventSource _source;
    private readonly Func<int, string?> _exeOfPid;
    private readonly Func<Guid, (int Pid, string? Path)?> _fallback;
    private readonly IFilterEventSink _sink;
    private readonly TimeProvider _time;
    private long _events;

    public BpfEventMonitor(
        IBpfEventSource source,
        Func<int, string?> exeOfPid,
        Func<Guid, (int Pid, string? Path)?> fallback,
        IFilterEventSink sink,
        TimeProvider time)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _exeOfPid = exeOfPid ?? throw new ArgumentNullException(nameof(exeOfPid));
        _fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public const string IdPrefix = "bpf-";

    public long EventsEmitted => Interlocked.Read(ref _events);

    public async Task RunAsync(CancellationToken ct)
    {
        await foreach (var line in _source.ReadLinesAsync(ct).ConfigureAwait(false))
        {
            if (BpfEventParser.TryParse(line) is { } flow)
            {
                Publish(flow);
            }
        }
    }

    /// <summary>Emits the pair for one record (pure apart from the lookups; used by tests).</summary>
    public void Publish(BpfFlowEvent flow)
    {
        ArgumentNullException.ThrowIfNull(flow);
        var path = _exeOfPid(flow.Pid);
        var pid = flow.Pid;
        if (path is null && flow.RuleId is { } ruleId && _fallback(ruleId) is { } app)
        {
            path = app.Path;
        }

        var now = _time.GetUtcNow();
        var id = string.Create(CultureInfo.InvariantCulture, $"{IdPrefix}{Interlocked.Increment(ref _events)}");
        var trace = new NftTraceEvent(
            "bpf",
            NftRuleCompiler.OutputChain,
            flow.ProtocolName,
            flow.LocalAddress,
            0,
            flow.RemoteAddress,
            flow.RemotePort,
            flow.Verdict,
            flow.RuleId);
        _sink.Emit(FilterEventFormatter.FlowOpen(id, trace, pid, path, now));
        _sink.Emit(FilterEventFormatter.FlowClose(id, now));
    }
}
