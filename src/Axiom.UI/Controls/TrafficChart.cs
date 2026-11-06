// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Specialized;
using System.Windows.Controls;
using System.Windows.Input;
using Axiom.UI.Services;
using System.Windows;
using System.Windows.Media;

namespace Axiom.UI.Controls;

/// <summary>
/// Lightweight WPF throughput chart with labelled rates, missing-sample gaps,
/// crosshair hover and interactive first-observed connection markers.
/// </summary>
public sealed class TrafficChart : FrameworkElement
{
    private const double PlotLeft = 70;
    private const double PlotRight = 10;
    private const double PlotTop = 10;
    private const double PlotBottom = 20;
    private int _hoverSeriesIndex = -1;
    private IReadOnlyList<ConnectionMarkerHit> _markerHits = [];

    public static readonly DependencyProperty UploadProperty = DependencyProperty.Register(
        nameof(Upload),
        typeof(IEnumerable<double>),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnSeriesChanged));

    public static readonly DependencyProperty DownloadProperty = DependencyProperty.Register(
        nameof(Download),
        typeof(IEnumerable<double>),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnSeriesChanged));

    public static readonly DependencyProperty SamplesProperty = DependencyProperty.Register(
        nameof(Samples),
        typeof(IEnumerable<ThroughputSample>),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnSamplesChanged));

    public static readonly DependencyProperty UploadBrushProperty = DependencyProperty.Register(
        nameof(UploadBrush),
        typeof(Brush),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty DownloadBrushProperty = DependencyProperty.Register(
        nameof(DownloadBrush),
        typeof(Brush),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty GridBrushProperty = DependencyProperty.Register(
        nameof(GridBrush),
        typeof(Brush),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MarkersProperty = DependencyProperty.Register(
        nameof(Markers),
        typeof(IReadOnlyList<ConnectionChartMarker>),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MarkerBrushProperty = DependencyProperty.Register(
        nameof(MarkerBrush),
        typeof(Brush),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ChartStartProperty = DependencyProperty.Register(
        nameof(ChartStart),
        typeof(DateTimeOffset),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(default(DateTimeOffset), FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ChartEndProperty = DependencyProperty.Register(
        nameof(ChartEnd),
        typeof(DateTimeOffset),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(default(DateTimeOffset), FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty RateUnitProperty = DependencyProperty.Register(
        nameof(RateUnit), typeof(string), typeof(TrafficChart),
        new FrameworkPropertyMetadata("Auto", FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty IsLiveProperty = DependencyProperty.Register(
        nameof(IsLive), typeof(bool), typeof(TrafficChart),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SelectedMarkerIndexProperty = DependencyProperty.Register(
        nameof(SelectedMarkerIndex), typeof(int), typeof(TrafficChart),
        new FrameworkPropertyMetadata(-1,
            FrameworkPropertyMetadataOptions.BindsTwoWayByDefault |
            FrameworkPropertyMetadataOptions.AffectsRender));

    public string RateUnit
    {
        get => (string)GetValue(RateUnitProperty);
        set => SetValue(RateUnitProperty, value);
    }

    public bool IsLive
    {
        get => (bool)GetValue(IsLiveProperty);
        set => SetValue(IsLiveProperty, value);
    }

    public IReadOnlyList<ConnectionChartMarker>? Markers
    {
        get => (IReadOnlyList<ConnectionChartMarker>?)GetValue(MarkersProperty);
        set => SetValue(MarkersProperty, value);
    }

    public DateTimeOffset ChartStart
    {
        get => (DateTimeOffset)GetValue(ChartStartProperty);
        set => SetValue(ChartStartProperty, value);
    }

    public DateTimeOffset ChartEnd
    {
        get => (DateTimeOffset)GetValue(ChartEndProperty);
        set => SetValue(ChartEndProperty, value);
    }

    public int SelectedMarkerIndex
    {
        get => (int)GetValue(SelectedMarkerIndexProperty);
        set => SetValue(SelectedMarkerIndexProperty, value);
    }

    private INotifyCollectionChanged? _uploadSource;
    private INotifyCollectionChanged? _downloadSource;
    private INotifyCollectionChanged? _samplesSource;

    public TrafficChart()
    {
        // Keep a tooltip object present from the start. WPF starts its hover timer when the
        // pointer enters; assigning a different ToolTip only from OnMouseMove can therefore
        // leave the dynamically generated rate tooltip invisible.
        ToolTip = new ToolTip { Content = "Hover over the chart for measured rates." };

        Loaded += (_, _) =>
        {
            Attach(Upload, ref _uploadSource);
            Attach(Download, ref _downloadSource);
            Attach(Samples, ref _samplesSource);
        };
        Unloaded += (_, _) =>
        {
            Detach(ref _uploadSource);
            Detach(ref _downloadSource);
            Detach(ref _samplesSource);
        };
    }

    public IEnumerable<double>? Upload
    {
        get => (IEnumerable<double>?)GetValue(UploadProperty);
        set => SetValue(UploadProperty, value);
    }

    public IEnumerable<double>? Download
    {
        get => (IEnumerable<double>?)GetValue(DownloadProperty);
        set => SetValue(DownloadProperty, value);
    }

    public IEnumerable<ThroughputSample>? Samples
    {
        get => (IEnumerable<ThroughputSample>?)GetValue(SamplesProperty);
        set => SetValue(SamplesProperty, value);
    }

    public Brush? UploadBrush
    {
        get => (Brush?)GetValue(UploadBrushProperty);
        set => SetValue(UploadBrushProperty, value);
    }

    public Brush? DownloadBrush
    {
        get => (Brush?)GetValue(DownloadBrushProperty);
        set => SetValue(DownloadBrushProperty, value);
    }

    public Brush? GridBrush
    {
        get => (Brush?)GetValue(GridBrushProperty);
        set => SetValue(GridBrushProperty, value);
    }

    public Brush? MarkerBrush
    {
        get => (Brush?)GetValue(MarkerBrushProperty);
        set => SetValue(MarkerBrushProperty, value);
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        ArgumentNullException.ThrowIfNull(drawingContext);

        var width = ActualWidth;
        var height = ActualHeight;
        if (width < PlotLeft + PlotRight + 10 || height < PlotTop + PlotBottom + 10)
        {
            return;
        }

        // Transparent hit-test surface: mouse interactions must also work over empty plot space.
        drawingContext.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, width, height));

        var plotWidth = width - PlotLeft - PlotRight;
        var bottom = height - PlotBottom;
        IReadOnlyList<ThroughputSample> samples = IsLive ? MaterializeSamples(Samples) : [];
        var valid = samples
            .SelectMany(sample => new[] { sample.Upload, sample.Download })
            .Where(value => double.IsFinite(value) && value >= 0)
            .ToList();
        var peak = valid.Count == 0 ? 0 : valid.Max();
        var scalePeak = Math.Max(1, peak * 1.18);

        var gridPen = new Pen(GridBrush ?? Brushes.Gray, 0.7);
        for (var line = 0; line <= 4; line++)
        {
            var y = PlotTop + ((bottom - PlotTop) * line / 4.0);
            drawingContext.DrawLine(gridPen, new Point(PlotLeft, y), new Point(width - PlotRight, y));
            DrawLabel(drawingContext, ByteFormatter.Rate(scalePeak * (4 - line) / 4, RateUnit),
                3, y - 6, Brushes.Gray);
        }

        var chartStart = ChartStart == default
            ? DateTimeOffset.UtcNow.AddMinutes(-5)
            : ChartStart;
        var chartEnd = ChartEnd == default || ChartEnd <= chartStart
            ? chartStart.AddMinutes(5)
            : ChartEnd;
        var span = chartEnd - chartStart;
        DrawLabel(
            drawingContext,
            TrafficChartGeometry.FormatAxisLabel(chartStart, span),
            PlotLeft,
            height - 14,
            Brushes.Gray);
        DrawLabelRight(
            drawingContext,
            TrafficChartGeometry.FormatAxisLabel(chartEnd, span),
            width - PlotRight,
            height - 14,
            Brushes.Gray);

        if (valid.Count == 0)
        {
            DrawLabel(drawingContext, IsLive
                    ? "Collecting measured traffic…"
                    : "No historical byte samples for this range",
                PlotLeft + 12, PlotTop + (bottom - PlotTop) / 2, Brushes.Gray);
        }

        DrawSeries(drawingContext, samples, true, DownloadBrush,
            chartStart, chartEnd, plotWidth, height, scalePeak);
        DrawSeries(drawingContext, samples, false, UploadBrush,
            chartStart, chartEnd, plotWidth, height, scalePeak);

        if (_hoverSeriesIndex >= 0 && IsLive && samples.Count > _hoverSeriesIndex)
        {
            var sample = samples[_hoverSeriesIndex];
            var x = TrafficChartGeometry.MapTimestamp(
                sample.Timestamp, chartStart, chartEnd, PlotLeft, plotWidth);
            var guidePen = new Pen(GridBrush ?? Brushes.Gray, 1) { DashStyle = DashStyles.Dash };
            drawingContext.DrawLine(guidePen, new Point(x, PlotTop), new Point(x, bottom));
            DrawHoverPoint(drawingContext, sample.Upload, UploadBrush, scalePeak, height, x);
            DrawHoverPoint(drawingContext, sample.Download, DownloadBrush, scalePeak, height, x);
        }

        DrawEventMarkers(drawingContext, width, height);
    }

    private void DrawHoverPoint(DrawingContext dc, double value, Brush? brush,
        double peak, double height, double x)
    {
        if (brush is null || !double.IsFinite(value))
        {
            return;
        }

        var bottom = height - PlotBottom;
        var y = bottom - (value / peak) * (bottom - PlotTop);
        dc.DrawEllipse(brush, new Pen(Brushes.White, 1), new Point(x, y), 3.5, 3.5);
    }

    private void DrawLabel(DrawingContext dc, string value, double x, double y, Brush brush)
    {
        var label = new FormattedText(
            value, System.Globalization.CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight, new Typeface("Segoe UI"), 10, brush,
            VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(label, new Point(x, y));
    }

    private void DrawLabelRight(DrawingContext dc, string value, double right, double y, Brush brush)
    {
        var label = new FormattedText(
            value, System.Globalization.CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight, new Typeface("Segoe UI"), 10, brush,
            VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(label, new Point(Math.Max(PlotLeft, right - label.Width), y));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var position = e.GetPosition(this);
        var x = position.X;
        var marker = HitMarker(position);
        if (marker >= 0)
        {
            Cursor = Cursors.Hand;
            SetHoverText(Markers is { } markers && marker < markers.Count
                ? markers[marker].Details
                : "Newly observed connection (not a threat determination)");
            _hoverSeriesIndex = -1;
        }
        else
        {
            Cursor = Cursors.Cross;
            var plotWidth = ActualWidth - PlotLeft - PlotRight;
            var samples = MaterializeSamples(Samples);
            if (IsLive && plotWidth > 0 && samples.Count > 1 &&
                x >= PlotLeft && x <= ActualWidth - PlotRight)
            {
                var chartStart = ChartStart == default
                    ? DateTimeOffset.UtcNow.AddMinutes(-5)
                    : ChartStart;
                var chartEnd = ChartEnd == default || ChartEnd <= chartStart
                    ? chartStart.AddMinutes(5)
                    : ChartEnd;
                var target = chartStart + ((chartEnd - chartStart) * ((x - PlotLeft) / plotWidth));
                var bestIndex = 0;
                var bestDistance = double.MaxValue;
                for (var index = 0; index < samples.Count; index++)
                {
                    var distance = Math.Abs((samples[index].Timestamp - target).TotalMilliseconds);
                    if (distance < bestDistance)
                    {
                        bestDistance = distance;
                        bestIndex = index;
                    }
                }

                _hoverSeriesIndex = bestIndex;
                var sample = samples[_hoverSeriesIndex];
                SetHoverText($"{sample.Timestamp.ToLocalTime():HH:mm:ss} local · system-wide" +
                    $"\nUpload: {ByteFormatter.Rate(sample.Upload, RateUnit)}" +
                    $"\nDownload: {ByteFormatter.Rate(sample.Download, RateUnit)}");
            }
            else
            {
                _hoverSeriesIndex = -1;
                SetHoverText("No recorded throughput for this range.");
            }
        }

        InvalidateVisual();
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        _hoverSeriesIndex = -1;
        Cursor = null;
        InvalidateVisual();
    }

    private void SetHoverText(string text)
    {
        if (ToolTip is ToolTip toolTip)
        {
            toolTip.Content = text;
            return;
        }

        ToolTip = new ToolTip { Content = text };
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        var position = e.GetPosition(this);
        var marker = HitMarker(position);
        SetCurrentValue(SelectedMarkerIndexProperty, marker);
        e.Handled = position.X >= PlotLeft && position.X <= ActualWidth - PlotRight;
    }

    private int HitMarker(Point point) =>
        TrafficChartGeometry.HitMarker(_markerHits, point.X, point.Y);

    private void DrawEventMarkers(DrawingContext drawingContext, double width, double height)
    {
        if (Markers is not { Count: > 0 } markers || MarkerBrush is null)
        {
            _markerHits = [];
            return;
        }

        var chartStart = ChartStart == default
            ? DateTimeOffset.UtcNow.AddMinutes(-5)
            : ChartStart;
        var chartEnd = ChartEnd == default || ChartEnd <= chartStart
            ? chartStart.AddMinutes(5)
            : ChartEnd;
        var plotWidth = width - PlotLeft - PlotRight;
        _markerHits = TrafficChartGeometry.LayoutMarkers(
            markers,
            chartStart,
            chartEnd,
            PlotLeft,
            plotWidth,
            PlotTop,
            height - PlotBottom);
        _markerHits = _markerHits
            .Select(hit => hit with
            {
                X = Math.Clamp(hit.X, PlotLeft + hit.Radius, width - PlotRight - hit.Radius),
            })
            .ToArray();

        var linePen = new Pen(MarkerBrush, 1)
        {
            DashStyle = new DashStyle([4, 4], 0),
        };
        linePen.Freeze();

        foreach (var hit in _markerHits)
        {
            var marker = markers[hit.Index];
            var x = Math.Clamp(hit.X, PlotLeft + hit.Radius, width - PlotRight - hit.Radius);
            drawingContext.DrawLine(
                linePen,
                new Point(x, hit.Y + hit.Radius),
                new Point(x, height - PlotBottom));
            drawingContext.DrawEllipse(
                MarkerBrush,
                hit.Index == SelectedMarkerIndex ? new Pen(Brushes.White, 2) : null,
                new Point(x, hit.Y),
                hit.Radius,
                hit.Radius);

            var text = new FormattedText(
                marker.Label,
                System.Globalization.CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI"),
                10,
                Brushes.White,
                VisualTreeHelper.GetDpi(this).PixelsPerDip);
            drawingContext.DrawText(
                text,
                new Point(x - (text.Width / 2), hit.Y - (text.Height / 2)));
        }
    }

    private static void OnSamplesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var chart = (TrafficChart)d;
        chart.Detach(ref chart._samplesSource);
        if (chart.IsLoaded)
        {
            chart.Attach(e.NewValue as IEnumerable<ThroughputSample>, ref chart._samplesSource);
        }

        chart.InvalidateVisual();
    }

    private static void OnSeriesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var chart = (TrafficChart)d;
        var target = ReferenceEquals(e.Property, UploadProperty) ? 0 : 1;

        if (target == 0)
        {
            chart.Detach(ref chart._uploadSource);
            if (chart.IsLoaded)
            {
                chart.Attach(e.NewValue as IEnumerable<double>, ref chart._uploadSource);
            }
        }
        else
        {
            chart.Detach(ref chart._downloadSource);
            if (chart.IsLoaded)
            {
                chart.Attach(e.NewValue as IEnumerable<double>, ref chart._downloadSource);
            }
        }

        chart.InvalidateVisual();
    }

    private static IReadOnlyList<double> Materialize(IEnumerable<double>? series)
    {
        if (series is null)
        {
            return [];
        }

        return series as IReadOnlyList<double> ?? series.ToList();
    }

    private static IReadOnlyList<ThroughputSample> MaterializeSamples(
        IEnumerable<ThroughputSample>? samples)
    {
        if (samples is null)
        {
            return [];
        }

        return samples as IReadOnlyList<ThroughputSample> ?? samples.ToList();
    }

    private void Attach<T>(IEnumerable<T>? series, ref INotifyCollectionChanged? field)
    {
        if (series is INotifyCollectionChanged notifier)
        {
            notifier.CollectionChanged += OnSeriesCollectionChanged;
            field = notifier;
        }
    }

    private void Detach(ref INotifyCollectionChanged? field)
    {
        if (field is not null)
        {
            field.CollectionChanged -= OnSeriesCollectionChanged;
            field = null;
        }
    }

    private void OnSeriesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) =>
        InvalidateVisual();

    private static void DrawSeries(
        DrawingContext dc,
        IReadOnlyList<ThroughputSample> samples,
        bool download,
        Brush? brush,
        DateTimeOffset start,
        DateTimeOffset end,
        double plotWidth,
        double height,
        double scalePeak)
    {
        if (brush is null || samples.Count < 2)
        {
            return;
        }

        var bottom = height - PlotBottom;
        double ValueAt(int index) => download ? samples[index].Download : samples[index].Upload;
        Point PointAt(int index) => new(
            TrafficChartGeometry.MapTimestamp(samples[index].Timestamp, start, end, PlotLeft, plotWidth),
            bottom - Math.Clamp(ValueAt(index) / scalePeak, 0, 1) * (bottom - PlotTop));

        // Invalid samples produce gaps. They must never be painted as zero activity.
        var pen = new Pen(brush, 1.7) { LineJoin = PenLineJoin.Round };
        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            var inSegment = false;
            for (var i = 0; i < samples.Count; i++)
            {
                if (!double.IsFinite(ValueAt(i)) || ValueAt(i) < 0)
                {
                    inSegment = false;
                    continue;
                }

                if (!inSegment)
                {
                    ctx.BeginFigure(PointAt(i), isFilled: false, isClosed: false);
                    inSegment = true;
                }
                else
                {
                    ctx.LineTo(PointAt(i), isStroked: true, isSmoothJoin: true);
                }
            }
        }

        line.Freeze();
        dc.DrawGeometry(null, pen, line);

        var startIndex = 0;
        while (startIndex < samples.Count)
        {
            while (startIndex < samples.Count &&
                   (!double.IsFinite(ValueAt(startIndex)) || ValueAt(startIndex) < 0))
            {
                startIndex++;
            }

            var endIndex = startIndex;
            while (endIndex < samples.Count &&
                   double.IsFinite(ValueAt(endIndex)) &&
                   ValueAt(endIndex) >= 0)
            {
                endIndex++;
            }

            if (endIndex - startIndex >= 2)
            {
                var area = new StreamGeometry();
                using (var ctx = area.Open())
                {
                    ctx.BeginFigure(new Point(PointAt(startIndex).X, bottom), true, true);
                    for (var i = startIndex; i < endIndex; i++)
                    {
                        ctx.LineTo(PointAt(i), false, true);
                    }

                    ctx.LineTo(new Point(PointAt(endIndex - 1).X, bottom), false, true);
                }

                area.Freeze();
                dc.PushOpacity(0.10);
                dc.DrawGeometry(brush, null, area);
                dc.Pop();
            }

            startIndex = endIndex;
        }
    }
}
