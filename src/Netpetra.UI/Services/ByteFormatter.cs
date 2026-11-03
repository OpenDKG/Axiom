// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Netpetra.UI.Services;

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
}
