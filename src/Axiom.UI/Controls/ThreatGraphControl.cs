// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Windows;
using System.Windows.Media;
using Axiom.Contracts.Blackbox;

namespace Axiom.UI.Controls;

/// <summary>
/// Lightweight native rendering of the local verified-threat graph. It deliberately uses the
/// dashboard's category vocabulary and colours, but draws with WPF primitives so Axiom does not
/// need a WebView or a second browser process.
/// </summary>
public sealed class ThreatGraphControl : FrameworkElement
{
    private const int MaxLeavesPerCategory = 6;

    private static readonly Dictionary<string, (string Label, Color Color)> Categories =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["dependency"] = ("Dependency", Color.FromRgb(0xF5, 0x9E, 0x0B)),
            ["injection"] = ("Prompt injection", Color.FromRgb(0xFB, 0x71, 0x85)),
            ["escalation"] = ("Escalation", Color.FromRgb(0xEF, 0x44, 0x44)),
            ["fileaccess"] = ("File access", Color.FromRgb(0x3B, 0x82, 0xF6)),
            ["skill"] = ("Suspicious skill", Color.FromRgb(0xA7, 0x8B, 0xFA)),
            ["secret"] = ("Secret exposure", Color.FromRgb(0xF9, 0x73, 0x16)),
            ["ioc"] = ("IOC", Color.FromRgb(0x14, 0xB8, 0xA6)),
            ["other"] = ("Other", Color.FromRgb(0x94, 0xA3, 0xB8)),
        };

    public static readonly DependencyProperty ThreatsProperty = DependencyProperty.Register(
        nameof(Threats),
        typeof(IReadOnlyList<BlackboxGraphThreat>),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty CategoryTotalsProperty = DependencyProperty.Register(
        nameof(CategoryTotals),
        typeof(IReadOnlyDictionary<string, int>),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TotalProperty = DependencyProperty.Register(
        nameof(Total),
        typeof(int),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata(0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StateTextProperty = DependencyProperty.Register(
        nameof(StateText),
        typeof(string),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata("Verified graph", FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty TextBrushProperty = DependencyProperty.Register(
        nameof(TextBrush),
        typeof(Brush),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata(Brushes.Gainsboro, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MutedBrushProperty = DependencyProperty.Register(
        nameof(MutedBrush),
        typeof(Brush),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SurfaceBrushProperty = DependencyProperty.Register(
        nameof(SurfaceBrush),
        typeof(Brush),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata(Brushes.Transparent, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty BorderBrushProperty = DependencyProperty.Register(
        nameof(BorderBrush),
        typeof(Brush),
        typeof(ThreatGraphControl),
        new FrameworkPropertyMetadata(Brushes.DimGray, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<BlackboxGraphThreat>? Threats
    {
        get => (IReadOnlyList<BlackboxGraphThreat>?)GetValue(ThreatsProperty);
        set => SetValue(ThreatsProperty, value);
    }

    public IReadOnlyDictionary<string, int>? CategoryTotals
    {
        get => (IReadOnlyDictionary<string, int>?)GetValue(CategoryTotalsProperty);
        set => SetValue(CategoryTotalsProperty, value);
    }

    public int Total
    {
        get => (int)GetValue(TotalProperty);
        set => SetValue(TotalProperty, value);
    }

    public string StateText
    {
        get => (string)GetValue(StateTextProperty);
        set => SetValue(StateTextProperty, value);
    }

    public Brush TextBrush
    {
        get => (Brush)GetValue(TextBrushProperty);
        set => SetValue(TextBrushProperty, value);
    }

    public Brush MutedBrush
    {
        get => (Brush)GetValue(MutedBrushProperty);
        set => SetValue(MutedBrushProperty, value);
    }

    public Brush SurfaceBrush
    {
        get => (Brush)GetValue(SurfaceBrushProperty);
        set => SetValue(SurfaceBrushProperty, value);
    }

    public Brush BorderBrush
    {
        get => (Brush)GetValue(BorderBrushProperty);
        set => SetValue(BorderBrushProperty, value);
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        ArgumentNullException.ThrowIfNull(drawingContext);

        var width = ActualWidth;
        var height = ActualHeight;
        if (width < 200 || height < 160)
        {
            return;
        }

        drawingContext.DrawRectangle(SurfaceBrush, null, new Rect(0, 0, width, height));
        var center = new Point(width / 2, height / 2);
        var radius = Math.Min(width, height) / 2;
        var threats = Materialize(Threats);
        var slices = BuildSlices(threats);

        if (slices.Count == 0)
        {
            DrawEmptyState(drawingContext, center, radius);
            return;
        }

        var categoryRadius = Math.Max(58, radius * 0.48);
        var leafRadius = Math.Max(34, radius * 0.18);
        var span = Math.PI * 2 / slices.Count;
        var accent = new SolidColorBrush(Color.FromRgb(0x5E, 0xEA, 0xD4));

        DrawHub(
            drawingContext,
            center,
            radius > 150 ? 34 : 28,
            accent,
            "Verified graph",
            Total > 0 ? $"{FormatCount(Total)} threats" : $"{threats.Count} loaded");

        for (var categoryIndex = 0; categoryIndex < slices.Count; categoryIndex++)
        {
            var slice = slices[categoryIndex];
            var (label, color) = Categories.TryGetValue(slice.Key, out var meta)
                ? meta
                : Categories["other"];
            var categoryAngle = -Math.PI / 2 + (categoryIndex * span);
            var categoryPoint = Polar(center, categoryRadius, categoryAngle);
            var categoryBrush = new SolidColorBrush(color);
            var edgePen = new Pen(new SolidColorBrush(Color.FromArgb(105, color.R, color.G, color.B)), 1.1);
            var hubRadius = radius > 150 ? 23 : 19;

            drawingContext.DrawLine(edgePen, center, categoryPoint);
            drawingContext.DrawEllipse(
                new SolidColorBrush(Color.FromArgb(42, color.R, color.G, color.B)),
                new Pen(categoryBrush, 1.5),
                categoryPoint,
                hubRadius,
                hubRadius);
            DrawText(
                drawingContext,
                FormatCount(slice.Count),
                categoryPoint.X,
                categoryPoint.Y - 6,
                10,
                TextBrush,
                center: true);

            var labelY = categoryPoint.Y + hubRadius + 6;
            if (labelY > height - 26)
            {
                labelY = categoryPoint.Y - hubRadius - 24;
            }

            DrawWrappedText(drawingContext, label, categoryPoint.X, labelY, 9, MutedBrush, 120);

            var leaves = slice.Threats
                .OrderByDescending(threat => SeverityRank(threat.Severity))
                .ThenBy(threat => threat.DisplayName, StringComparer.OrdinalIgnoreCase)
                .Take(MaxLeavesPerCategory)
                .ToList();
            for (var leafIndex = 0; leafIndex < leaves.Count; leafIndex++)
            {
                var leaf = leaves[leafIndex];
                var offset = leaves.Count == 1
                    ? 0
                    : ((leafIndex - (leaves.Count - 1) / 2.0) / Math.Max(1, (leaves.Count - 1) / 2.0)) * (span * 0.30);
                var leafPoint = Polar(categoryPoint, leafRadius, categoryAngle + offset);
                var severityColor = SeverityColor(leaf.Severity);
                var outline = new Pen(
                    new SolidColorBrush(severityColor),
                    SeverityRank(leaf.Severity) >= 4 ? 2 : 1);

                drawingContext.DrawLine(
                    new Pen(new SolidColorBrush(Color.FromArgb(70, color.R, color.G, color.B)), 0.8),
                    categoryPoint,
                    leafPoint);
                drawingContext.DrawEllipse(new SolidColorBrush(color), outline, leafPoint, 4.5, 4.5);
            }
        }
    }

    private List<CategorySlice> BuildSlices(IReadOnlyList<BlackboxGraphThreat> threats)
    {
        var totals = CategoryTotals;
        var groups = threats
            .GroupBy(threat => NormalizeCategory(threat.Category), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.OrdinalIgnoreCase);
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (totals is not null)
        {
            foreach (var key in totals.Keys)
            {
                keys.Add(NormalizeCategory(key));
            }
        }

        foreach (var key in groups.Keys)
        {
            keys.Add(key);
        }

        return keys
            .Select(key =>
            {
                var loaded = groups.TryGetValue(key, out var items) ? items : [];
                var count = totals is not null && totals.TryGetValue(key, out var total)
                    ? total
                    : loaded.Count;
                return new CategorySlice(key, count, loaded);
            })
            .Where(slice => slice.Count > 0)
            .OrderByDescending(slice => slice.Count)
            .ThenBy(slice => slice.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void DrawEmptyState(DrawingContext drawingContext, Point center, double radius)
    {
        var outline = new Pen(BorderBrush, 1.4);
        drawingContext.DrawEllipse(SurfaceBrush, outline, center, radius > 150 ? 32 : 26, radius > 150 ? 32 : 26);
        DrawText(drawingContext, "Verified graph", center.X, center.Y - 7, 11, TextBrush, center: true);
        DrawText(drawingContext, StateText, center.X, center.Y + 9, 10, MutedBrush, center: true);
        DrawText(
            drawingContext,
            "Waiting for a non-empty verified graph from the local DKG node.",
            center.X,
            center.Y + 48,
            10,
            MutedBrush,
            center: true);
    }

    private void DrawHub(
        DrawingContext drawingContext,
        Point point,
        double size,
        Brush brush,
        string label,
        string detail)
    {
        drawingContext.DrawEllipse(
            new SolidColorBrush(Color.FromArgb(38, 255, 255, 255)),
            new Pen(brush, 1.6),
            point,
            size,
            size);
        DrawText(drawingContext, label, point.X, point.Y - 7, 10, TextBrush, center: true);
        DrawText(drawingContext, detail, point.X, point.Y + 7, 9, MutedBrush, center: true);
    }

    private void DrawText(
        DrawingContext drawingContext,
        string value,
        double x,
        double y,
        double size,
        Brush brush,
        bool center)
    {
        var text = CreateText(value, size, brush, center);
        drawingContext.DrawText(text, new Point(center ? x - text.Width / 2 : x, y));
    }

    private void DrawWrappedText(
        DrawingContext drawingContext,
        string value,
        double x,
        double y,
        double size,
        Brush brush,
        double maxWidth)
    {
        var text = CreateText(value, size, brush, center: true);
        text.MaxTextWidth = maxWidth;
        drawingContext.DrawText(text, new Point(x - maxWidth / 2, y));
    }

    private FormattedText CreateText(string value, double size, Brush brush, bool center) =>
        new(
            value,
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            new Typeface("Segoe UI"),
            size,
            brush,
            VisualTreeHelper.GetDpi(this).PixelsPerDip)
        {
            TextAlignment = center ? TextAlignment.Center : TextAlignment.Left,
        };

    private static IReadOnlyList<BlackboxGraphThreat> Materialize(
        IReadOnlyList<BlackboxGraphThreat>? threats) =>
        threats ?? [];

    private static string NormalizeCategory(string category)
    {
        var key = category.Trim().ToLowerInvariant();
        return Categories.ContainsKey(key) ? key : "other";
    }

    private static Point Polar(Point origin, double radius, double angle) =>
        new(origin.X + Math.Cos(angle) * radius, origin.Y + Math.Sin(angle) * radius);

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    };

    private static Color SeverityColor(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => Color.FromRgb(0xEF, 0x44, 0x44),
        "high" => Color.FromRgb(0xFB, 0x71, 0x85),
        "medium" => Color.FromRgb(0xF5, 0x9E, 0x0B),
        "low" => Color.FromRgb(0x3B, 0x82, 0xF6),
        _ => Color.FromRgb(0x94, 0xA3, 0xB8),
    };

    private static string FormatCount(int value) => value switch
    {
        >= 1_000_000 => (value / 1_000_000d).ToString("0.0", CultureInfo.InvariantCulture) + "M",
        >= 1_000 => (value / 1_000d).ToString("0", CultureInfo.InvariantCulture) + "K",
        _ => value.ToString(CultureInfo.InvariantCulture),
    };

    private sealed record CategorySlice(string Key, int Count, IReadOnlyList<BlackboxGraphThreat> Threats);
}
