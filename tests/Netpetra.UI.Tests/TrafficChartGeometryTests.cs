// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Netpetra.UI.Controls;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class TrafficChartGeometryTests
{
    [Fact]
    public void Timestamp_maps_to_the_matching_x_position()
    {
        var start = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var end = start.AddSeconds(100);

        Assert.Equal(70, TrafficChartGeometry.MapTimestamp(start, start, end, 70, 300), 3);
        Assert.Equal(145, TrafficChartGeometry.MapTimestamp(start.AddSeconds(25), start, end, 70, 300), 3);
        Assert.Equal(370, TrafficChartGeometry.MapTimestamp(end, start, end, 70, 300), 3);
    }

    [Fact]
    public void Timestamp_outside_the_window_is_clamped()
    {
        var start = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var end = start.AddMinutes(5);

        Assert.Equal(70, TrafficChartGeometry.MapTimestamp(start.AddMinutes(-1), start, end, 70, 300), 3);
        Assert.Equal(370, TrafficChartGeometry.MapTimestamp(end.AddMinutes(1), start, end, 70, 300), 3);
    }

    [Fact]
    public void Marker_hit_testing_requires_both_axes()
    {
        ConnectionMarkerHit[] hits =
        [
            new(0, 100, 50, 9),
        ];

        Assert.Equal(0, TrafficChartGeometry.HitMarker(hits, 104, 54));
        Assert.Equal(-1, TrafficChartGeometry.HitMarker(hits, 120, 50));
        Assert.Equal(-1, TrafficChartGeometry.HitMarker(hits, 100, 90));
    }

    [Fact]
    public void Dense_markers_stack_into_separate_rows()
    {
        var start = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var end = start.AddMinutes(5);
        var markers = new[]
        {
            new ConnectionChartMarker(start.AddSeconds(10), "1", "first"),
            new ConnectionChartMarker(start.AddSeconds(11), "2", "second"),
            new ConnectionChartMarker(start.AddSeconds(12), "3", "third"),
        };

        var hits = TrafficChartGeometry.LayoutMarkers(markers, start, end, 70, 300, 10, 200);

        Assert.Equal(3, hits.Count);
        Assert.True(hits[1].Y > hits[0].Y);
        Assert.True(hits[2].Y > hits[1].Y);
    }

    [Fact]
    public void Axis_labels_follow_the_selected_time_span()
    {
        var value = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var local = value.ToLocalTime();

        Assert.Equal(local.ToString("HH:mm:ss", CultureInfo.InvariantCulture), TrafficChartGeometry.FormatAxisLabel(value, TimeSpan.FromMinutes(5)));
        Assert.Equal(local.ToString("HH:mm", CultureInfo.InvariantCulture), TrafficChartGeometry.FormatAxisLabel(value, TimeSpan.FromHours(24)));
        Assert.Equal(local.ToString("MM-dd", CultureInfo.InvariantCulture), TrafficChartGeometry.FormatAxisLabel(value, TimeSpan.FromDays(7)));
    }
}
