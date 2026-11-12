// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text.Json;

namespace Axiom.Infrastructure.Linux.Nft;

/// <summary>Counter of one nft rule, attributed to the Axiom rule through its comment.</summary>
public sealed record NftRuleCounter(Guid RuleId, int Part, long Handle, long Packets, long Bytes, string Chain);

/// <summary>Outcome of <see cref="NftTable.ApplyAsync"/>.</summary>
public sealed record NftApplyResult(bool Success, string Error);

/// <summary>
/// Owns <c>table inet axiom</c>: atomic apply of a generation (<c>nft -f -</c> with the
/// delete-and-recreate idiom, so the table is replaced in one transaction), listing (<c>nft -j</c>),
/// and deletion. Only Axiom's table is ever touched; other tables (firewalld, ufw, docker) are never
/// listed or flushed.
/// </summary>
public sealed class NftTable
{
    private readonly INftRunner _nft;

    public NftTable(INftRunner nft)
    {
        _nft = nft ?? throw new ArgumentNullException(nameof(nft));
    }

    public async Task<NftApplyResult> ApplyAsync(string script, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(script);
        var result = await _nft.RunAsync(["-f", "-"], script, ct).ConfigureAwait(false);
        return result.Succeeded
            ? new NftApplyResult(true, string.Empty)
            : new NftApplyResult(false, Trim(result.StandardError.Length > 0 ? result.StandardError : result.StandardOutput));
    }

    /// <summary>Checks a script without committing it (<c>nft -c</c>); needs root for the netlink cache.</summary>
    public async Task<NftApplyResult> CheckAsync(string script, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(script);
        var result = await _nft.RunAsync(["-c", "-f", "-"], script, ct).ConfigureAwait(false);
        return result.Succeeded ? new NftApplyResult(true, string.Empty) : new NftApplyResult(false, Trim(result.StandardError));
    }

    public async Task<bool> ExistsAsync(CancellationToken ct)
    {
        var result = await _nft.RunAsync(["list", "table", "inet", NftRuleCompiler.TableName], null, ct).ConfigureAwait(false);
        return result.Succeeded;
    }

    public async Task<NftApplyResult> DeleteAsync(CancellationToken ct)
    {
        var result = await _nft.RunAsync(["delete", "table", "inet", NftRuleCompiler.TableName], null, ct).ConfigureAwait(false);
        return result.Succeeded || result.StandardError.Contains("No such file or directory", StringComparison.Ordinal)
            ? new NftApplyResult(true, string.Empty)
            : new NftApplyResult(false, Trim(result.StandardError));
    }

    /// <summary>Lists the table as nft JSON (<c>nft -j list table inet axiom</c>); null when absent.</summary>
    public async Task<string?> ListJsonAsync(CancellationToken ct)
    {
        var result = await _nft.RunAsync(["-j", "list", "table", "inet", NftRuleCompiler.TableName], null, ct).ConfigureAwait(false);
        return result.Succeeded ? result.StandardOutput : null;
    }

    /// <summary>Generation recorded in the table comment, or null when the table is absent or foreign.</summary>
    public async Task<long?> ReadGenerationAsync(CancellationToken ct) =>
        ParseGeneration(await ListJsonAsync(ct).ConfigureAwait(false));

    public async Task<IReadOnlyList<NftRuleCounter>> ReadCountersAsync(CancellationToken ct) =>
        ParseCounters(await ListJsonAsync(ct).ConfigureAwait(false));

    /// <summary>Parses the table comment (<c>axiom generation N</c>) out of <c>nft -j list table</c> output.</summary>
    public static long? ParseGeneration(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            foreach (var item in Items(document.RootElement))
            {
                if (item.TryGetProperty("table", out var table) &&
                    table.TryGetProperty("name", out var name) &&
                    name.ValueKind == JsonValueKind.String &&
                    name.GetString() == NftRuleCompiler.TableName &&
                    table.TryGetProperty("comment", out var comment) &&
                    comment.ValueKind == JsonValueKind.String)
                {
                    var text = comment.GetString() ?? string.Empty;
                    const string prefix = "axiom generation ";
                    if (text.StartsWith(prefix, StringComparison.Ordinal) &&
                        long.TryParse(text[prefix.Length..], NumberStyles.None, CultureInfo.InvariantCulture, out var generation))
                    {
                        return generation;
                    }
                }
            }
        }
        catch (JsonException)
        {
            return null;
        }

        return null;
    }

    /// <summary>
    /// Extracts <c>counter</c> values of every rule whose comment is <c>axiom:&lt;ruleId&gt;:&lt;n&gt;</c>
    /// from <c>nft -j list table inet axiom</c> output. Unknown or malformed entries are skipped.
    /// </summary>
    public static IReadOnlyList<NftRuleCounter> ParseCounters(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        var counters = new List<NftRuleCounter>();
        try
        {
            using var document = JsonDocument.Parse(json);
            foreach (var item in Items(document.RootElement))
            {
                if (!item.TryGetProperty("rule", out var rule) ||
                    !rule.TryGetProperty("comment", out var comment) ||
                    comment.ValueKind != JsonValueKind.String ||
                    !TryParseComment(comment.GetString(), out var ruleId, out var part))
                {
                    continue;
                }

                long packets = 0;
                long bytes = 0;
                if (rule.TryGetProperty("expr", out var expressions) && expressions.ValueKind == JsonValueKind.Array)
                {
                    foreach (var expression in expressions.EnumerateArray())
                    {
                        if (expression.TryGetProperty("counter", out var counter) && counter.ValueKind == JsonValueKind.Object)
                        {
                            packets = Long(counter, "packets");
                            bytes = Long(counter, "bytes");
                        }
                    }
                }

                var handle = rule.TryGetProperty("handle", out var handleValue) && handleValue.TryGetInt64(out var h) ? h : -1;
                var chain = rule.TryGetProperty("chain", out var chainValue) && chainValue.ValueKind == JsonValueKind.String
                    ? chainValue.GetString() ?? string.Empty
                    : string.Empty;
                counters.Add(new NftRuleCounter(ruleId, part, handle, packets, bytes, chain));
            }
        }
        catch (JsonException)
        {
            return counters;
        }

        return counters;
    }

    /// <summary>Parses the <c>axiom:&lt;guid&gt;:&lt;n&gt;</c> comment the compiler stamps on every rule.</summary>
    public static bool TryParseComment(string? comment, out Guid ruleId, out int part)
    {
        ruleId = Guid.Empty;
        part = 0;
        if (comment is null || !comment.StartsWith(NftRuleCompiler.CommentPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        var rest = comment[NftRuleCompiler.CommentPrefix.Length..];
        var colon = rest.LastIndexOf(':');
        if (colon <= 0)
        {
            return false;
        }

        return Guid.TryParseExact(rest[..colon], "D", out ruleId) &&
               int.TryParse(rest[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out part);
    }

    private static IEnumerable<JsonElement> Items(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("nftables", out var list) ||
            list.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var item in list.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object)
            {
                yield return item;
            }
        }
    }

    private static long Long(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.TryGetInt64(out var number) ? number : 0;

    private static string Trim(string text)
    {
        var trimmed = text.Trim();
        return trimmed.Length > 512 ? trimmed[..512] : trimmed;
    }
}
