// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Specialized;
using System.Windows.Controls;
using System.Windows.Input;
using Netpetra.UI.Services;
using System.Windows;
using System.Windows.Media;

namespace Netpetra.UI.Controls;

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

    public static readonly DependencyProperty MarkerPositionsProperty = DependencyProperty.Register(
        nameof(MarkerPositions),
        typeof(IReadOnlyList<double>),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MarkerBrushProperty = DependencyProperty.Register(
        nameof(MarkerBrush),
        typeof(Brush),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MarkerLabelsProperty = DependencyProperty.Register(
        nameof(MarkerLabels),
        typeof(IReadOnlyList<string>),
        typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty RateUnitProperty = DependencyProperty.Register(
        nameof(RateUnit), typeof(string), typeof(TrafficChart),
        new FrameworkPropertyMetadata("Auto", FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty IsLiveProperty = DependencyProperty.Register(
        nameof(IsLive), typeof(bool), typeof(TrafficChart),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MarkerDetailsProperty = DependencyProperty.Register(
        nameof(MarkerDetails), typeof(IReadOnlyList<string>), typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

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

    public IReadOnlyList<string>? MarkerDetails
    {
        get => (IReadOnlyList<string>?)GetValue(MarkerDetailsProperty);
        set => SetValue(MarkerDetailsProperty, value);
    }

    public int SelectedMarkerIndex
    {
        get => (int)GetValue(SelectedMarkerIndexProperty);
        set => SetValue(SelectedMarkerIndexProperty, value);
    }

    private INotifyCollectionChanged? _uploadSource;
    private INotifyCollectionChanged? _downloadSource;

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
        };
        Unloaded += (_, _) =>
        {
            Detach(ref _uploadSource);
            Detach(ref _downloadSource);
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

    /// <summary>Normalised 0..1 positions of event markers on the time axis.</summary>
    public IReadOnlyList<double>? MarkerPositions
    {
        get => (IReadOnlyList<double>?)GetValue(MarkerPositionsProperty);
        set => SetValue(MarkerPositionsProperty, value);
    }

    public Brush? MarkerBrush
    {
        get => (Brush?)GetValue(MarkerBrushProperty);
        set => SetValue(MarkerBrushProperty, value);
    }

    /// <summary>Optional short labels drawn on top of each marker (for example 1, 2, 3).</summary>
    public IReadOnlyList<string>? MarkerLabels
    {
        get => (IReadOnlyList<string>?)GetValue(MarkerLabelsProperty);
        set => SetValue(MarkerLabelsProperty, value);
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
        IReadOnlyList<double> uploadValues = IsLive ? Materialize(Upload) : Array.Empty<double>();
        IReadOnlyList<double> downloadValues = IsLive ? Materialize(Download) : Array.Empty<double>();
        var valid = uploadValues.Concat(downloadValues)
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

        DrawLabel(drawingContext, IsLive ? "-5m" : "Unavailable", PlotLeft, height - 14, Brushes.Gray);
        DrawLabel(drawingContext, IsLive ? "Now" : "No recorded byte history",
            IsLive ? width - 36 : PlotLeft + 80, height - 14, Brushes.Gray);

        if (valid.Count == 0)
        {
            DrawLabel(drawingContext, IsLive ? "Collecting measured traffic…" : "No historical byte measurements available",
                PlotLeft + 12, PlotTop + (bottom - PlotTop) / 2, Brushes.Gray);
        }

        DrawSeries(drawingContext, downloadValues, DownloadBrush, plotWidth, height, scalePeak);
        DrawSeries(drawingContext, uploadValues, UploadBrush, plotWidth, height, scalePeak);

        if (_hoverSeriesIndex >= 0 && IsLive && downloadValues.Count > _hoverSeriesIndex)
        {
            var x = PlotLeft + (_hoverSeriesIndex / (double)(downloadValues.Count - 1)) * plotWidth;
            var guidePen = new Pen(GridBrush ?? Brushes.Gray, 1) { DashStyle = DashStyles.Dash };
            drawingContext.DrawLine(guidePen, new Point(x, PlotTop), new Point(x, bottom));
            DrawHoverPoint(drawingContext, uploadValues, UploadBrush, scalePeak, height, x);
            DrawHoverPoint(drawingContext, downloadValues, DownloadBrush, scalePeak, height, x);
        }

        DrawEventMarkers(drawingContext, width, height);
    }

    private void DrawHoverPoint(DrawingContext dc, IReadOnlyList<double> series, Brush? brush,
        double peak, double height, double x)
    {
        if (brush is null || _hoverSeriesIndex >= series.Count)
        {
            return;
        }

        var value = series[_hoverSeriesIndex];
        if (!double.IsFinite(value))
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

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var x = e.GetPosition(this).X;
        var marker = HitMarker(x);
        if (marker >= 0)
        {
            Cursor = Cursors.Hand;
            SetHoverText(MarkerDetails is { } details && marker < details.Count
                ? details[marker] : "Newly observed connection (not a threat determination)");
            _hoverSeriesIndex = -1;
        }
        else
        {
            Cursor = Cursors.Cross;
            var plotWidth = ActualWidth - PlotLeft - PlotRight;
            var upload = Materialize(Upload);
            var download = Materialize(Download);
            if (IsLive && plotWidth > 0 && upload.Count > 1 && x >= PlotLeft && x <= ActualWidth - PlotRight)
            {
                _hoverSeriesIndex = Math.Clamp(
                    (int)Math.Round((x - PlotLeft) / plotWidth * (upload.Count - 1)),
                    0, upload.Count - 1);
                var up = upload[_hoverSeriesIndex];
                var down = _hoverSeriesIndex < download.Count ? download[_hoverSeriesIndex] : double.NaN;
                var secondsAgo = upload.Count - 1 - _hoverSeriesIndex;
                SetHoverText($"≈{secondsAgo} s ago · system-wide" +
                    $"\nUpload: {ByteFormatter.Rate(up, RateUnit)}" +
                    $"\nDownload: {ByteFormatter.Rate(down, RateUnit)}");
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
        var marker = HitMarker(e.GetPosition(this).X);
        if (marker < 0)
        {
            return;
        }

        SetCurrentValue(SelectedMarkerIndexProperty, marker);
        e.Handled = true;
    }

    private int HitMarker(double x)
    {
        if (MarkerPositions is not { Count: > 0 } positions)
        {
            return -1;
        }

        var plotWidth = ActualWidth - PlotLeft - PlotRight;
        for (var i = positions.Count - 1; i >= 0; i--)
        {
            if (Math.Abs(x - (PlotLeft + positions[i] * plotWidth)) <= 7)
            {
                return i;
            }
        }

        return -1;
    }

    private void DrawEventMarkers(DrawingContext drawingContext, double width, double height)
    {
        if (MarkerPositions is not { Count: > 0 } positions || MarkerBrush is null)
        {
            return;
        }

        var linePen = new Pen(MarkerBrush, 1)
        {
            DashStyle = new DashStyle([4, 4], 0),
        };
        linePen.Freeze();

        var labels = MarkerLabels;
        var lastLabelX = double.NaN;
        var labelRow = 0;
        for (var index = 0; index < positions.Count; index++)
        {
            var x = PlotLeft + Math.Clamp(positions[index], 0, 1) * (width - PlotLeft - PlotRight);
            var label = labels is not null && index < labels.Count ? labels[index] : null;

            if (label is null)
            {
                drawingContext.DrawLine(linePen, new Point(x, 8), new Point(x, height - PlotBottom));

                var triangle = new StreamGeometry();
                using (var context = triangle.Open())
                {
                    context.BeginFigure(new Point(x - 3, 0), isFilled: true, isClosed: true);
                    context.LineTo(new Point(x + 3, 0), isStroked: false, isSmoothJoin: false);
                    context.LineTo(new Point(x, 5), isStroked: false, isSmoothJoin: false);
                }

                triangle.Freeze();
                drawingContext.DrawGeometry(MarkerBrush, null, triangle);
                continue;
            }

            var badgeX = Math.Clamp(x, PlotLeft + 9, width - PlotRight - 9);
            labelRow = !double.IsNaN(lastLabelX) && Math.Abs(badgeX - lastLabelX) < 14
                ? labelRow + 1
                : 0;
            lastLabelX = badgeX;
            var badgeY = 14 + (labelRow * 19);
            const double radius = 9;
            drawingContext.DrawLine(linePen, new Point(x, badgeY + radius), new Point(x, height - PlotBottom));
            drawingContext.DrawEllipse(MarkerBrush,
                index == SelectedMarkerIndex ? new Pen(Brushes.White, 2) : null,
                new Point(badgeX, badgeY), radius, radius);

            var text = new FormattedText(
                label,
                System.Globalization.CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI"),
                10,
                Brushes.White,
                VisualTreeHelper.GetDpi(this).PixelsPerDip);
            drawingContext.DrawText(
                text,
                new Point(badgeX - (text.Width / 2), badgeY - (text.Height / 2)));
        }
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

    private void Attach(IEnumerable<double>? series, ref INotifyCollectionChanged? field)
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
        DrawingContext dc, IReadOnlyList<double> values, Brush? brush,
        double plotWidth, double height, double scalePeak)
    {
        if (brush is null || values.Count < 2)
        {
            return;
        }

        var bottom = height - PlotBottom;
        var step = plotWidth / (values.Count - 1);
        Point PointAt(int i) => new(
            PlotLeft + i * step,
            bottom - Math.Clamp(values[i] / scalePeak, 0, 1) * (bottom - PlotTop));

        // Invalid samples produce gaps. They must never be painted as zero activity.
        var pen = new Pen(brush, 1.7) { LineJoin = PenLineJoin.Round };
        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            var inSegment = false;
            for (var i = 0; i < values.Count; i++)
            {
                if (!double.IsFinite(values[i]) || values[i] < 0)
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

        var start = 0;
        while (start < values.Count)
        {
            while (start < values.Count && (!double.IsFinite(values[start]) || values[start] < 0))
            {
                start++;
            }

            var end = start;
            while (end < values.Count && double.IsFinite(values[end]) && values[end] >= 0)
            {
                end++;
            }

            if (end - start >= 2)
            {
                var area = new StreamGeometry();
                using (var ctx = area.Open())
                {
                    ctx.BeginFigure(new Point(PlotLeft + start * step, bottom), true, true);
                    for (var i = start; i < end; i++)
                    {
                        ctx.LineTo(PointAt(i), false, true);
                    }

                    ctx.LineTo(new Point(PlotLeft + (end - 1) * step, bottom), false, true);
                }

                area.Freeze();
                dc.PushOpacity(0.10);
                dc.DrawGeometry(brush, null, area);
                dc.Pop();
            }

            start = end;
        }
    }
}
