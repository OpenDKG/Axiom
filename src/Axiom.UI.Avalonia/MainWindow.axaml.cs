// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;

namespace Axiom.UI.Avalonia;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        UpdateCaptionGlyph();
        AddHandler(PointerPressedEvent, OnWindowPointerPressed, RoutingStrategies.Tunnel, handledEventsToo: true);
    }

    private void OnWindowPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed || WindowState == WindowState.Maximized)
        {
            return;
        }

        const double edge = 6;
        var point = e.GetPosition(this);
        var left = point.X <= edge;
        var right = point.X >= Bounds.Width - edge;
        var top = point.Y <= edge;
        var bottom = point.Y >= Bounds.Height - edge;

        if (top && left)
        {
            BeginResizeDrag(WindowEdge.NorthWest, e);
        }
        else if (top && right)
        {
            BeginResizeDrag(WindowEdge.NorthEast, e);
        }
        else if (bottom && left)
        {
            BeginResizeDrag(WindowEdge.SouthWest, e);
        }
        else if (bottom && right)
        {
            BeginResizeDrag(WindowEdge.SouthEast, e);
        }
        else if (top)
        {
            BeginResizeDrag(WindowEdge.North, e);
        }
        else if (bottom)
        {
            BeginResizeDrag(WindowEdge.South, e);
        }
        else if (left)
        {
            BeginResizeDrag(WindowEdge.West, e);
        }
        else if (right)
        {
            BeginResizeDrag(WindowEdge.East, e);
        }
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == WindowStateProperty)
        {
            UpdateCaptionGlyph();
        }
    }

    private void OnTitleBarPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        // Caption buttons handle their own clicks; do not start a window drag from them.
        if (FindButton(e.Source as Visual) is not null)
        {
            return;
        }

        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        BeginMoveDrag(e);
    }

    private void OnMinimizeClicked(object? sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void OnMaximizeClicked(object? sender, RoutedEventArgs e) => ToggleMaximize();

    private void OnCloseClicked(object? sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize() =>
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    private void UpdateCaptionGlyph()
    {
        if (MaximizeButton is null)
        {
            return;
        }

        MaximizeButton.Content = WindowState == WindowState.Maximized ? "\uE923" : "\uE922";
        ToolTip.SetTip(
            MaximizeButton,
            WindowState == WindowState.Maximized ? "Restore" : "Maximize");
    }

    private static Button? FindButton(Visual? visual)
    {
        while (visual is not null)
        {
            if (visual is Button button)
            {
                return button;
            }

            visual = visual.GetVisualParent();
        }

        return null;
    }
}
