// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Axiom.Contracts.Blackbox;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Native rendering of the local verified-threat graph. It uses the dashboard's category
/// vocabulary and colours but draws everything locally; no WebView or second browser process.
/// </summary>
public sealed class ThreatGraphControl : Control
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

    public static readonly StyledProperty<IReadOnlyList<BlackboxGraphThreat>?> ThreatsProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IReadOnlyList<BlackboxGraphThreat>?>(nameof(Threats));

    public static readonly StyledProperty<IReadOnlyDictionary<string, int>?> CategoryTotalsProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IReadOnlyDictionary<string, int>?>(nameof(CategoryTotals));

    public static readonly StyledProperty<int> TotalProperty =
        AvaloniaProperty.Register<ThreatGraphControl, int>(nameof(Total));

    public static readonly StyledProperty<string> StateTextProperty =
        AvaloniaProperty.Register<ThreatGraphControl, string>(nameof(StateText), "Verified graph");

    public static readonly StyledProperty<IBrush> TextBrushProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IBrush>(
            nameof(TextBrush),
            new SolidColorBrush(Color.Parse("#E6EDF3")));

    public static readonly StyledProperty<IBrush> MutedBrushProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IBrush>(
            nameof(MutedBrush),
            new SolidColorBrush(Color.Parse("#8A98A8")));

    public static readonly StyledProperty<IBrush> SurfaceBrushProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IBrush>(
            nameof(SurfaceBrush),
            new SolidColorBrush(Color.Parse("#161B22")));

    public static readonly StyledProperty<IBrush> BorderBrushProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IBrush>(
            nameof(BorderBrush),
            new SolidColorBrush(Color.Parse("#2E3A47")));

    public static readonly StyledProperty<IBrush?> AccentBrushProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IBrush?>(nameof(AccentBrush));

    public static readonly StyledProperty<IBrush?> HubFillBrushProperty =
        AvaloniaProperty.Register<ThreatGraphControl, IBrush?>(nameof(HubFillBrush));

    static ThreatGraphControl()
    {
        AffectsRender<ThreatGraphControl>(
            ThreatsProperty,
            CategoryTotalsProperty,
            TotalProperty,
            StateTextProperty,
            TextBrushProperty,
            MutedBrushProperty,
            SurfaceBrushProperty,
            BorderBrushProperty,
            AccentBrushProperty,
            HubFillBrushProperty);
    }

    public IReadOnlyList<BlackboxGraphThreat>? Threats
    {
        get => GetValue(ThreatsProperty);
        set => SetValue(ThreatsProperty, value);
    }

    public IReadOnlyDictionary<string, int>? CategoryTotals
    {
        get => GetValue(CategoryTotalsProperty);
        set => SetValue(CategoryTotalsProperty, value);
    }

    public int Total
    {
        get => GetValue(TotalProperty);
        set => SetValue(TotalProperty, value);
    }

    public string StateText
    {
        get => GetValue(StateTextProperty);
        set => SetValue(StateTextProperty, value);
    }

    public IBrush TextBrush
    {
        get => GetValue(TextBrushProperty);
        set => SetValue(TextBrushProperty, value);
    }

    public IBrush MutedBrush
    {
        get => GetValue(MutedBrushProperty);
        set => SetValue(MutedBrushProperty, value);
    }

    public IBrush SurfaceBrush
    {
        get => GetValue(SurfaceBrushProperty);
        set => SetValue(SurfaceBrushProperty, value);
    }

    public IBrush BorderBrush
    {
        get => GetValue(BorderBrushProperty);
        set => SetValue(BorderBrushProperty, value);
    }

    public IBrush? AccentBrush
    {
        get => GetValue(AccentBrushProperty);
        set => SetValue(AccentBrushProperty, value);
    }

    public IBrush? HubFillBrush
    {
        get => GetValue(HubFillBrushProperty);
        set => SetValue(HubFillBrushProperty, value);
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var width = Bounds.Width;
        var height = Bounds.Height;
        if (width < 200 || height < 160)
        {
            return;
        }

        var surface = ResolveThemeBrush(SurfaceBrushProperty, "Axiom.Surface", SurfaceBrush);
        context.FillRectangle(surface, new Rect(0, 0, width, height));
        var center = new Point(width / 2, height / 2);
        var radius = Math.Min(width, height) / 2;
        var threats = Threats ?? [];
        var slices = BuildSlices(threats);

        if (slices.Count == 0)
        {
            DrawEmptyState(context, center, radius);
            return;
        }

        var categoryRadius = Math.Max(58, radius * 0.48);
        var leafRadius = Math.Max(34, radius * 0.18);
        var span = Math.PI * 2 / slices.Count;
        var accent = AccentBrush ?? ResolveBrush("Axiom.Accent", "#FAFAFA");

        DrawHub(
            context,
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
            var categoryAngle = -Math.PI / 2 + categoryIndex * span;
            var categoryPoint = Polar(center, categoryRadius, categoryAngle);
            var categoryBrush = new SolidColorBrush(color);
            var edgePen = new Pen(new SolidColorBrush(Color.FromArgb(105, color.R, color.G, color.B)), 1.1);
            var hubRadius = radius > 150 ? 23 : 19;

            context.DrawLine(edgePen, center, categoryPoint);
            context.DrawEllipse(
                new SolidColorBrush(Color.FromArgb(42, color.R, color.G, color.B)),
                new Pen(categoryBrush, 1.5),
                categoryPoint,
                hubRadius,
                hubRadius);
            DrawText(
                context,
                FormatCount(slice.Count),
                categoryPoint.X,
                categoryPoint.Y - 4,
                10,
                ResolveThemeBrush(TextBrushProperty, "Axiom.TextPrimary", TextBrush),
                center: true);

            var labelY = categoryPoint.Y + hubRadius + 6;
            if (labelY > height - 26)
            {
                labelY = categoryPoint.Y - hubRadius - 24;
            }

            DrawWrappedText(context, label, categoryPoint.X, labelY, 9, ResolveThemeBrush(MutedBrushProperty, "Axiom.TextMuted", MutedBrush), 120);

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
                    : (leafIndex - (leaves.Count - 1) / 2.0) / Math.Max(1, (leaves.Count - 1) / 2.0) * (span * 0.30);
                var leafPoint = Polar(categoryPoint, leafRadius, categoryAngle + offset);
                var severityColor = SeverityColor(leaf.Severity);
                var outline = new Pen(
                    new SolidColorBrush(severityColor),
                    SeverityRank(leaf.Severity) >= 4 ? 2 : 1);

                context.DrawLine(
                    new Pen(new SolidColorBrush(Color.FromArgb(70, color.R, color.G, color.B)), 0.8),
                    categoryPoint,
                    leafPoint);
                context.DrawEllipse(new SolidColorBrush(color), outline, leafPoint, 4.5, 4.5);
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

    private void DrawEmptyState(DrawingContext context, Point center, double radius)
    {
        var border = ResolveThemeBrush(BorderBrushProperty, "Axiom.Border", BorderBrush);
        var surface = ResolveThemeBrush(SurfaceBrushProperty, "Axiom.Surface", SurfaceBrush);
        var text = ResolveThemeBrush(TextBrushProperty, "Axiom.TextPrimary", TextBrush);
        var muted = ResolveThemeBrush(MutedBrushProperty, "Axiom.TextMuted", MutedBrush);
        var outline = new Pen(border, 1.4);
        context.DrawEllipse(surface, outline, center, radius > 150 ? 32 : 26, radius > 150 ? 32 : 26);
        DrawText(context, "Verified graph", center.X, center.Y - 7, 11, text, center: true);
        DrawText(context, StateText, center.X, center.Y + 9, 10, muted, center: true);
        DrawText(
            context,
            "Waiting for a non-empty verified graph from the local DKG node.",
            center.X,
            center.Y + 48,
            10,
            muted,
            center: true);
    }

    private void DrawHub(DrawingContext context, Point point, double size, IBrush brush, string label, string detail)
    {
        var fill = HubFillBrush ?? ResolveBrush("Axiom.AccentSoft", "#20FFFFFF");
        var text = ResolveThemeBrush(TextBrushProperty, "Axiom.TextPrimary", TextBrush);
        var muted = ResolveThemeBrush(MutedBrushProperty, "Axiom.TextMuted", MutedBrush);
        context.DrawEllipse(
            fill,
            new Pen(brush, 1.6),
            point,
            size,
            size);
        DrawText(context, label, point.X, point.Y - 16, 10, text, center: true);
        DrawText(context, detail, point.X, point.Y + 2, 9, muted, center: true);
    }

    private IBrush ResolveThemeBrush(StyledProperty<IBrush> property, string key, IBrush fallback) =>
        IsSet(property) ? GetValue(property) : ResolveBrush(key, fallback);

    private static IBrush ResolveBrush(string key, string fallbackHex) =>
        ResolveBrush(key, new SolidColorBrush(Color.Parse(fallbackHex)));

    private static IBrush ResolveBrush(string key, IBrush fallback) =>
        Application.Current?.TryFindResource(key, Application.Current.ActualThemeVariant, out var value) == true &&
        value is IBrush brush
            ? brush
            : fallback;

    private void DrawText(
        DrawingContext context,
        string value,
        double x,
        double y,
        double size,
        IBrush brush,
        bool center)
    {
        var text = CreateText(value, size, brush);
        context.DrawText(text, new Point(center ? x - text.Width / 2 : x, y));
    }

    private void DrawWrappedText(
        DrawingContext context,
        string value,
        double x,
        double y,
        double size,
        IBrush brush,
        double maxWidth)
    {
        var text = CreateText(value, size, brush);
        text.MaxTextWidth = maxWidth;
        context.DrawText(text, new Point(x - maxWidth / 2, y));
    }

    private static FormattedText CreateText(string value, double size, IBrush brush) =>
        new(
            value,
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            Typeface.Default,
            size,
            brush);

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
