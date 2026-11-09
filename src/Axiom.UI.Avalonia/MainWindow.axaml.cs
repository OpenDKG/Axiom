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
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        // Selectable text handles the pointer before the row does. Keep row selection working when
        // the user clicks text inside a ListBox item, while still allowing the text selection.
        SelectContainingListItem(e.Source as Visual);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == WindowStateProperty)
        {
            UpdateCaptionGlyph();
        }
    }

    private void OnMinimizeClicked(object? sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void OnAlertsClicked(object? sender, RoutedEventArgs e) =>
        AlertsPopup.IsOpen = !AlertsPopup.IsOpen;

    private void OnAlertItemClicked(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: AlertRecord alert } && DataContext is ShellViewModel shell)
        {
            shell.OpenAlert(alert);
        }

        AlertsPopup.IsOpen = false;
    }

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

    private static void SelectContainingListItem(Visual? visual)
    {
        while (visual is not null)
        {
            if (visual is ListBoxItem item && item.GetVisualParent() is ListBox list)
            {
                list.SelectedItem = item.DataContext;
                return;
            }

            visual = visual.GetVisualParent();
        }
    }
}
