// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.UI.Controls;

/// <summary>One first-observed connection annotation on the throughput chart.</summary>
public sealed record ConnectionChartMarker(
    DateTimeOffset Timestamp,
    string Label,
    string Details,
    bool IsThreat = false);

/// <summary>Rendered hit target for one marker badge.</summary>
public readonly record struct ConnectionMarkerHit(
    int Index,
    double X,
    double Y,
    double Radius);

/// <summary>
/// Pure timestamp-to-pixel and marker hit-testing logic used by <see cref="TrafficChart"/>.
/// Keeping it separate makes the chart geometry testable without a WPF render pass.
/// </summary>
public static class TrafficChartGeometry
{
    public static double MapTimestamp(
        DateTimeOffset timestamp,
        DateTimeOffset start,
        DateTimeOffset end,
        double plotLeft,
        double plotWidth)
    {
        var span = (end - start).TotalSeconds;
        if (span <= 0 || plotWidth <= 0)
        {
            return plotLeft;
        }

        var ratio = (timestamp - start).TotalSeconds / span;
        return plotLeft + (Math.Clamp(ratio, 0, 1) * plotWidth);
    }

    public static IReadOnlyList<ConnectionMarkerHit> LayoutMarkers(
        IReadOnlyList<ConnectionChartMarker> markers,
        DateTimeOffset start,
        DateTimeOffset end,
        double plotLeft,
        double plotWidth,
        double top,
        double bottom,
        double radius = 9,
        double rowHeight = 19,
        double minSeparation = 14)
    {
        var hits = new List<ConnectionMarkerHit>(markers.Count);
        var rowLastX = new List<double>();
        for (var index = 0; index < markers.Count; index++)
        {
            var x = MapTimestamp(markers[index].Timestamp, start, end, plotLeft, plotWidth);
            var row = 0;
            while (row < rowLastX.Count && Math.Abs(x - rowLastX[row]) < minSeparation)
            {
                row++;
            }

            if (row == rowLastX.Count)
            {
                rowLastX.Add(x);
            }
            else
            {
                rowLastX[row] = x;
            }

            var y = Math.Min(top + radius + (row * rowHeight), bottom - radius);
            hits.Add(new ConnectionMarkerHit(index, x, y, radius));
        }

        return hits;
    }

    public static int HitMarker(
        IReadOnlyList<ConnectionMarkerHit> hits,
        double x,
        double y,
        double extra = 3)
    {
        for (var index = hits.Count - 1; index >= 0; index--)
        {
            var hit = hits[index];
            var dx = x - hit.X;
            var dy = y - hit.Y;
            var radius = hit.Radius + extra;
            if ((dx * dx) + (dy * dy) <= radius * radius)
            {
                return hit.Index;
            }
        }

        return -1;
    }

    public static string FormatAxisLabel(DateTimeOffset value, TimeSpan span)
    {
        var local = value.ToLocalTime();
        return span.TotalHours <= 2
            ? local.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture)
            : span.TotalDays <= 2
                ? local.ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture)
                : local.ToString("MM-dd", System.Globalization.CultureInfo.InvariantCulture);
    }
}
