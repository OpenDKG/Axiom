// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Media;

namespace Netrigil.UI.Controls;

/// <summary>
/// Minimal dependency-free line chart for two series. Deliberately small: FND-001 only needs to
/// prove the shell renders a series; a full charting library is evaluated when real data volume
/// (FND-004) justifies the dependency.
/// </summary>
public sealed class TrafficChart : FrameworkElement
{
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

    private INotifyCollectionChanged? _uploadSource;
    private INotifyCollectionChanged? _downloadSource;

    public TrafficChart()
    {
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

    protected override void OnRender(DrawingContext drawingContext)
    {
        ArgumentNullException.ThrowIfNull(drawingContext);

        var width = ActualWidth;
        var height = ActualHeight;
        if (width < 2 || height < 2)
        {
            return;
        }

        var uploadValues = Materialize(Upload);
        var downloadValues = Materialize(Download);

        if (GridBrush is not null)
        {
            var pen = new Pen(GridBrush, 1);
            pen.Freeze();
            for (var line = 1; line <= 3; line++)
            {
                var y = height * line / 4.0;
                drawingContext.DrawLine(pen, new Point(0, y), new Point(width, y));
            }
        }

        var peak = Math.Max(
            uploadValues.Count == 0 ? 0 : uploadValues.Max(),
            downloadValues.Count == 0 ? 0 : downloadValues.Max());
        var scalePeak = Math.Max(1, peak * 1.18);

        DrawEventMarkers(drawingContext, width, height);

        DrawSeries(drawingContext, downloadValues, DownloadBrush, width, height, scalePeak);
        DrawSeries(drawingContext, uploadValues, UploadBrush, width, height, scalePeak);
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

        foreach (var position in positions)
        {
            var x = Math.Clamp(position, 0, 1) * width;

            drawingContext.DrawLine(linePen, new Point(x, 8), new Point(x, height));

            var triangle = new StreamGeometry();
            using (var context = triangle.Open())
            {
                context.BeginFigure(new Point(x - 3, 0), isFilled: true, isClosed: true);
                context.LineTo(new Point(x + 3, 0), isStroked: false, isSmoothJoin: false);
                context.LineTo(new Point(x, 5), isStroked: false, isSmoothJoin: false);
            }

            triangle.Freeze();
            drawingContext.DrawGeometry(MarkerBrush, null, triangle);
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
        DrawingContext drawingContext,
        IReadOnlyList<double> values,
        Brush? brush,
        double width,
        double height,
        double scalePeak)
    {
        if (brush is null || values.Count < 2)
        {
            return;
        }

        var step = width / (values.Count - 1);
        const double topPadding = 8;

        static double Y(double value, double scalePeak, double height, double topPadding)
        {
            var usable = Math.Max(1, height - topPadding);
            var normalised = Math.Clamp(value / scalePeak, 0, 1);
            return height - (normalised * usable);
        }

        var area = new StreamGeometry();
        using (var context = area.Open())
        {
            context.BeginFigure(new Point(0, height), isFilled: true, isClosed: true);
            for (var i = 0; i < values.Count; i++)
            {
                context.LineTo(
                    new Point(i * step, Y(values[i], scalePeak, height, topPadding)),
                    isStroked: false,
                    isSmoothJoin: false);
            }

            context.LineTo(new Point(width, height), isStroked: false, isSmoothJoin: false);
        }

        area.Freeze();

        drawingContext.PushOpacity(0.12);
        drawingContext.DrawGeometry(brush, null, area);
        drawingContext.Pop();

        var line = new StreamGeometry();
        using (var context = line.Open())
        {
            context.BeginFigure(
                new Point(0, Y(values[0], scalePeak, height, topPadding)),
                isFilled: false,
                isClosed: false);
            for (var i = 1; i < values.Count; i++)
            {
                context.LineTo(
                    new Point(i * step, Y(values[i], scalePeak, height, topPadding)),
                    isStroked: true,
                    isSmoothJoin: true);
            }
        }

        line.Freeze();

        var pen = new Pen(brush, 1.6)
        {
            LineJoin = PenLineJoin.Round,
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
        };
        pen.Freeze();

        drawingContext.DrawGeometry(null, pen, line);
    }
}
