// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;

namespace Axiom.Contracts.History;

/// <summary>
/// RFC 4180 CSV for the history table. Fields that a spreadsheet would evaluate as a formula are
/// prefixed with an apostrophe so exported host data cannot execute on the analyst's machine.
/// </summary>
public static class HistoryCsv
{
    public const string Header =
        "application,path,pid,protocol,local,remote,direction,state,quality,firstSeenUtc,lastSeenUtc";

    public static string Format(IEnumerable<HistoryRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);

        var builder = new StringBuilder();
        builder.Append(Header).Append("\r\n");

        foreach (var row in rows)
        {
            builder
                .Append(Field(row.AppDisplayName)).Append(',')
                .Append(Field(row.AppPath)).Append(',')
                .Append(row.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(',')
                .Append(Field(row.Protocol)).Append(',')
                .Append(Field(row.LocalEndpoint)).Append(',')
                .Append(Field(row.RemoteEndpoint)).Append(',')
                .Append(Field(row.Direction)).Append(',')
                .Append(Field(row.State)).Append(',')
                .Append(Field(row.Quality)).Append(',')
                .Append(Field(row.FirstSeenUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture))).Append(',')
                .Append(Field(row.LastSeenUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)))
                .Append("\r\n");
        }

        return builder.ToString();
    }

    internal static string Field(string? value)
    {
        value ??= string.Empty;

        // A leading = + - @ (or tab/CR) makes Excel/LibreOffice evaluate the cell as a formula.
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            value = "'" + value;
        }

        if (value.IndexOfAny([',', '"', '\r', '\n']) < 0)
        {
            return value;
        }

        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
