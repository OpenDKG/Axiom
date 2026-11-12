// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>Receives NDJSON lines in the macOS filter-event contract (docs/MACOS_ARCHITECTURE.md section 3.2).</summary>
public interface IFilterEventSink
{
    void Emit(string ndjsonLine);
}

/// <summary>
/// Formats engine events as the filter → daemon NDJSON contract so the daemon's
/// <c>FilterEventServer</c>/<c>FlowEventParser</c>/<c>FilterStatus</c>/<c>FlowTable</c> are reused
/// unchanged: <c>filter.hello</c> and <c>filter.rules</c> after every generation, and for each
/// blocked attempt seen by <c>nft monitor trace</c> a <c>flow.open</c> (verdict <c>block</c>, ruleId)
/// followed by a <c>flow.close</c> with zero bytes, exactly as the macOS filter does for drops.
/// </summary>
public static class FilterEventFormatter
{
    public const string Version = "nft-1";

    private static readonly JsonWriterOptions WriterOptions = new() { Indented = false, SkipValidation = false };

    public static string Hello(long generation, long dropped, DateTimeOffset now) =>
        Write(writer =>
        {
            writer.WriteString("type", "filter.hello");
            writer.WriteString("ts", Timestamp(now));
            writer.WriteString("version", Version);
            writer.WriteNumber("generation", generation);
            writer.WriteNumber("dropped", dropped);
        });

    public static string Rules(long generation, int applied, IEnumerable<NftRejectedRule> rejected, string? error, long dropped, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(rejected);
        return Write(writer =>
        {
            writer.WriteString("type", "filter.rules");
            writer.WriteString("ts", Timestamp(now));
            writer.WriteNumber("generation", generation);
            writer.WriteNumber("applied", applied);
            writer.WriteStartArray("rejected");
            foreach (var rule in rejected)
            {
                writer.WriteStartObject();
                writer.WriteString("id", rule.RuleId.ToString("D", CultureInfo.InvariantCulture));
                writer.WriteString("reason", rule.Reason);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            if (error is null)
            {
                writer.WriteNull("error");
            }
            else
            {
                writer.WriteString("error", error);
            }

            writer.WriteNumber("dropped", dropped);
        });
    }

    public static string FlowOpen(string id, NftTraceEvent trace, int pid, string? path, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(trace);
        return Write(writer =>
        {
            writer.WriteString("type", "flow.open");
            writer.WriteString("id", id);
            writer.WriteString("ts", Timestamp(now));
            writer.WriteNumber("pid", pid);
            if (path is null)
            {
                writer.WriteNull("path");
            }
            else
            {
                writer.WriteString("path", path);
            }

            writer.WriteString("direction", trace.Chain == NftRuleCompiler.InputChain ? "inbound" : "outbound");
            writer.WriteString("protocol", trace.Protocol is "tcp" or "udp" ? trace.Protocol : "other");
            writer.WriteString("localAddress", trace.LocalAddress);
            writer.WriteNumber("localPort", trace.LocalPort);
            writer.WriteString("remoteAddress", trace.RemoteAddress);
            writer.WriteNumber("remotePort", trace.RemotePort);
            writer.WriteNull("remoteHost");
            writer.WriteString("verdict", trace.Verdict);
            if (trace.RuleId is { } ruleId)
            {
                writer.WriteString("ruleId", ruleId.ToString("D", CultureInfo.InvariantCulture));
            }
            else
            {
                writer.WriteNull("ruleId");
            }

            writer.WriteNull("responsiblePid");
            writer.WriteNull("responsiblePath");
        });
    }

    public static string FlowClose(string id, DateTimeOffset now) =>
        Write(writer =>
        {
            writer.WriteString("type", "flow.close");
            writer.WriteString("id", id);
            writer.WriteString("ts", Timestamp(now));
            writer.WriteNumber("bytesIn", 0);
            writer.WriteNumber("bytesOut", 0);
        });

    private static string Timestamp(DateTimeOffset now) =>
        now.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    private static string Write(Action<Utf8JsonWriter> body)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartObject();
            body(writer);
            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }
}
