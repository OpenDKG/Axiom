// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Specialized;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Minimal measured-throughput chart. It plots the portable <c>TrafficEngine</c> samples and never
/// synthesizes history: a gap in the series stays a gap.
/// </summary>
public sealed class TrafficChartControl : Control
{
    public static readonly StyledProperty<IList<double>?> UploadSeriesProperty =
        AvaloniaProperty.Register<TrafficChartControl, IList<double>?>(nameof(UploadSeries));

    public static readonly StyledProperty<IList<double>?> DownloadSeriesProperty =
        AvaloniaProperty.Register<TrafficChartControl, IList<double>?>(nameof(DownloadSeries));

    public static readonly StyledProperty<IBrush?> GridLineBrushProperty =
        AvaloniaProperty.Register<TrafficChartControl, IBrush?>(nameof(GridLineBrush));

    public static readonly StyledProperty<IBrush?> UploadBrushProperty =
        AvaloniaProperty.Register<TrafficChartControl, IBrush?>(nameof(UploadBrush));

    public static readonly StyledProperty<IBrush?> DownloadBrushProperty =
        AvaloniaProperty.Register<TrafficChartControl, IBrush?>(nameof(DownloadBrush));

    public static readonly StyledProperty<IBrush?> MutedBrushProperty =
        AvaloniaProperty.Register<TrafficChartControl, IBrush?>(nameof(MutedBrush));

    private IBrush _muted = new SolidColorBrush(Color.Parse("#8A98A8"));
    private bool _isAttached;

    static TrafficChartControl()
    {
        AffectsRender<TrafficChartControl>(
            GridLineBrushProperty,
            UploadBrushProperty,
            DownloadBrushProperty,
            MutedBrushProperty);
    }

    public IList<double>? UploadSeries
    {
        get => GetValue(UploadSeriesProperty);
        set => SetValue(UploadSeriesProperty, value);
    }

    public IList<double>? DownloadSeries
    {
        get => GetValue(DownloadSeriesProperty);
        set => SetValue(DownloadSeriesProperty, value);
    }

    public IBrush? GridLineBrush
    {
        get => GetValue(GridLineBrushProperty);
        set => SetValue(GridLineBrushProperty, value);
    }

    public IBrush? UploadBrush
    {
        get => GetValue(UploadBrushProperty);
        set => SetValue(UploadBrushProperty, value);
    }

    public IBrush? DownloadBrush
    {
        get => GetValue(DownloadBrushProperty);
        set => SetValue(DownloadBrushProperty, value);
    }

    public IBrush? MutedBrush
    {
        get => GetValue(MutedBrushProperty);
        set => SetValue(MutedBrushProperty, value);
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _isAttached = true;
        AttachSeries(UploadSeries as INotifyCollectionChanged);
        AttachSeries(DownloadSeries as INotifyCollectionChanged);
        InvalidateVisual();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _isAttached = false;
        DetachSeries(UploadSeries as INotifyCollectionChanged);
        DetachSeries(DownloadSeries as INotifyCollectionChanged);
        base.OnDetachedFromVisualTree(e);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == UploadSeriesProperty || change.Property == DownloadSeriesProperty)
        {
            if (_isAttached)
            {
                DetachSeries(change.OldValue as INotifyCollectionChanged);
                AttachSeries(change.NewValue as INotifyCollectionChanged);
            }

            InvalidateVisual();
        }
    }

    private void AttachSeries(INotifyCollectionChanged? collection)
    {
        if (collection is null)
        {
            return;
        }

        collection.CollectionChanged -= OnSeriesChanged;
        collection.CollectionChanged += OnSeriesChanged;
    }

    private void DetachSeries(INotifyCollectionChanged? collection)
    {
        if (collection is null)
        {
            return;
        }

        collection.CollectionChanged -= OnSeriesChanged;
    }

    private void OnSeriesChanged(object? sender, NotifyCollectionChangedEventArgs e) => InvalidateVisual();

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var width = Bounds.Width;
        var height = Bounds.Height;
        if (width <= 4 || height <= 4)
        {
            return;
        }

        const double paddingLeft = 8;
        const double paddingRight = 54;
        const double paddingTop = 8;
        const double paddingBottom = 16;
        var plotWidth = Math.Max(1, width - paddingLeft - paddingRight);
        var plotHeight = Math.Max(1, height - paddingTop - paddingBottom);

        var gridPen = new Pen(GridLineBrush ?? ResolveBrush("Axiom.GridLine", "#2E3A47"), 1);
        var uploadPen = new Pen(UploadBrush ?? ResolveBrush("Axiom.Upload", "#5EEAD4"), 1.6);
        var downloadPen = new Pen(DownloadBrush ?? ResolveBrush("Axiom.Download", "#1F6FEB"), 1.6);
        _muted = MutedBrush ?? ResolveBrush("Axiom.TextMuted", "#8A98A8");

        for (var line = 0; line <= 4; line++)
        {
            var y = paddingTop + plotHeight * line / 4;
            context.DrawLine(gridPen, new Point(paddingLeft, y), new Point(paddingLeft + plotWidth, y));
        }

        var upload = UploadSeries;
        var download = DownloadSeries;
        var max = Math.Max(MaxFinite(upload), MaxFinite(download));
        if (max <= 0 || upload is null || download is null || upload.Count < 2)
        {
            DrawText(context, "No measured throughput yet", new Point(paddingLeft + 8, paddingTop + plotHeight / 2 - 8));
            return;
        }

        DrawSeries(context, upload, uploadPen, max, paddingLeft, paddingTop, plotWidth, plotHeight);
        DrawSeries(context, download, downloadPen, max, paddingLeft, paddingTop, plotWidth, plotHeight);

        DrawText(context, FormatRate(max), new Point(paddingLeft + plotWidth + 6, paddingTop - 4));
        DrawText(context, "up", new Point(paddingLeft + plotWidth + 6, paddingTop + 12));
        DrawText(context, "down", new Point(paddingLeft + plotWidth + 6, paddingTop + 26));
    }

    private static void DrawSeries(
        DrawingContext context,
        IList<double> values,
        Pen pen,
        double max,
        double left,
        double top,
        double width,
        double height)
    {
        var geometry = new StreamGeometry();
        using var stream = geometry.Open();
        var started = false;
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (double.IsNaN(value) || double.IsInfinity(value) || value < 0)
            {
                started = false;
                continue;
            }

            var x = left + width * index / Math.Max(1, values.Count - 1);
            var y = top + height - (value / max * height);
            if (!started)
            {
                stream.BeginFigure(new Point(x, y), isFilled: false);
                started = true;
            }
            else
            {
                stream.LineTo(new Point(x, y));
            }
        }

        context.DrawGeometry(null, pen, geometry);
    }

    private static double MaxFinite(IList<double>? values)
    {
        if (values is null)
        {
            return 0;
        }

        var max = 0d;
        foreach (var value in values)
        {
            if (double.IsFinite(value) && value > max)
            {
                max = value;
            }
        }

        return max;
    }

    private static string FormatRate(double bytesPerSecond) =>
        bytesPerSecond >= 1024 * 1024
            ? $"{bytesPerSecond / (1024 * 1024):0.0} MB/s"
            : $"{bytesPerSecond / 1024:0.0} KB/s";

    private void DrawText(DrawingContext context, string text, Point origin)
    {
        var formatted = new FormattedText(
            text,
            System.Globalization.CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            Typeface.Default,
            9,
            _muted);
        context.DrawText(formatted, origin);
    }

    private IBrush ResolveBrush(string key, string fallback) =>
        this.TryFindResource(key, out var value) && value is IBrush brush
            ? brush
            : new SolidColorBrush(Color.Parse(fallback));
}
