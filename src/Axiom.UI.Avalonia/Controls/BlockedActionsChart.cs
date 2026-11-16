// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Horizontal bars of blocked guard decisions per agent. It deliberately draws the same numbers
/// the dashboard reports instead of the vendor graph's unique-threat nodes, so thousands of
/// blocked tool calls are visible at a glance.
/// </summary>
public sealed class BlockedActionsChart : Control
{
    public static readonly StyledProperty<IReadOnlyList<AgentBlockBar>?> BarsProperty =
        AvaloniaProperty.Register<BlockedActionsChart, IReadOnlyList<AgentBlockBar>?>(nameof(Bars));

    public static readonly StyledProperty<IBrush> TextBrushProperty =
        AvaloniaProperty.Register<BlockedActionsChart, IBrush>(
            nameof(TextBrush), new SolidColorBrush(Color.FromRgb(0xE8, 0xE6, 0xE1)));

    public static readonly StyledProperty<IBrush> MutedBrushProperty =
        AvaloniaProperty.Register<BlockedActionsChart, IBrush>(
            nameof(MutedBrush), new SolidColorBrush(Color.FromRgb(0x8E, 0x8B, 0x84)));

    public static readonly StyledProperty<IBrush> BarBrushProperty =
        AvaloniaProperty.Register<BlockedActionsChart, IBrush>(
            nameof(BarBrush), new SolidColorBrush(Color.FromRgb(0xFF, 0x6A, 0x3D)));

    static BlockedActionsChart()
    {
        AffectsRender<BlockedActionsChart>(BarsProperty, TextBrushProperty, MutedBrushProperty, BarBrushProperty);
        AffectsMeasure<BlockedActionsChart>(BarsProperty);
    }

    public IReadOnlyList<AgentBlockBar>? Bars
    {
        get => GetValue(BarsProperty);
        set => SetValue(BarsProperty, value);
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

    public IBrush BarBrush
    {
        get => GetValue(BarBrushProperty);
        set => SetValue(BarBrushProperty, value);
    }

    private const double RowHeight = 26;
    private const double LabelWidth = 104;
    private const double ValueWidth = 52;

    protected override Size MeasureOverride(Size availableSize)
    {
        var rows = Bars?.Count ?? 0;
        var width = double.IsInfinity(availableSize.Width) ? 420 : availableSize.Width;
        return new Size(width, Math.Max(48, rows * RowHeight + 6));
    }

    public override void Render(DrawingContext context)
    {
        var bars = Bars;
        if (bars is null || bars.Count == 0)
        {
            DrawText(context, "No blocked actions recorded yet.", 4, 6, 12, MutedBrush);
            return;
        }

        var width = Math.Max(240, Bounds.Width);
        var maximum = Math.Max(1, bars.Max(bar => bar.Count));
        var barArea = Math.Max(40, width - LabelWidth - ValueWidth);
        var typeface = new Typeface("Segoe UI");

        for (var index = 0; index < bars.Count; index++)
        {
            var bar = bars[index];
            var y = index * RowHeight;
            var label = new FormattedText(
                bar.Label,
                CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                typeface,
                11.5,
                TextBrush);
            context.DrawText(label, new Point(0, y + 5));

            var barWidth = Math.Max(3, barArea * bar.Count / maximum);
            var rect = new Rect(LabelWidth, y + 5, barWidth, RowHeight - 12);
            context.DrawRectangle(BarBrush, null, rect, 3, 3);

            var value = new FormattedText(
                bar.Count.ToString(CultureInfo.InvariantCulture),
                CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                typeface,
                11.5,
                TextBrush);
            context.DrawText(value, new Point(LabelWidth + barWidth + 6, y + 5));
        }
    }

    private static void DrawText(DrawingContext context, string text, double x, double y, double size, IBrush brush)
    {
        var formatted = new FormattedText(
            text,
            CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight,
            new Typeface("Segoe UI"),
            size,
            brush);
        context.DrawText(formatted, new Point(x, y));
    }
}
