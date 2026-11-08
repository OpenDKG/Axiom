// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Presentation;

/// <summary>Display formatting only. Never used to make a measurement claim.</summary>
public static class ByteFormatter
{
    private static readonly string[] RateUnits = ["B/s", "KB/s", "MB/s", "GB/s"];

    private static readonly string[] ByteUnits = ["B", "KB", "MB", "GB", "TB"];

    public static string Rate(double bytesPerSecond)
    {
        if (double.IsNaN(bytesPerSecond) || double.IsInfinity(bytesPerSecond) || bytesPerSecond < 0)
        {
            return "—";
        }

        var value = bytesPerSecond;
        var unit = 0;
        while (value >= 1024 && unit < RateUnits.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{value.ToString(unit == 0 ? "0" : "0.0", CultureInfo.InvariantCulture)} {RateUnits[unit]}");
    }

    public static string Rate(double bytesPerSecond, string selectedUnit)
    {
        if (double.IsNaN(bytesPerSecond) || double.IsInfinity(bytesPerSecond) || bytesPerSecond < 0)
        {
            return "—";
        }

        if (selectedUnit is not ("KB/s" or "MB/s" or "GB/s"))
        {
            return Rate(bytesPerSecond);
        }

        var divisor = selectedUnit switch
        {
            "KB/s" => 1024d,
            "MB/s" => 1024d * 1024d,
            _ => 1024d * 1024d * 1024d,
        };

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{(bytesPerSecond / divisor).ToString("0.0", CultureInfo.InvariantCulture)} {selectedUnit}");
    }

    public static string Total(long bytes)
    {
        if (bytes <= 0)
        {
            return "0 B";
        }

        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < ByteUnits.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{value.ToString(unit == 0 ? "0" : "0.0", CultureInfo.InvariantCulture)} {ByteUnits[unit]}");
    }

    /// <summary>Megabytes for per-application totals; never invents a value for missing data.</summary>
    public static string Megabytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "0.00 MB";
        }

        var megabytes = bytes / (1024d * 1024d);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{(megabytes >= 100 ? megabytes.ToString("0.0", CultureInfo.InvariantCulture) : megabytes.ToString("0.00", CultureInfo.InvariantCulture))} MB");
    }
}
