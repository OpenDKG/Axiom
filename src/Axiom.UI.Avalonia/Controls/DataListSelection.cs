// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Attached behavior for data <see cref="ListBox"/> controls so clicking any cell (including on
/// right-click or nested visuals) selects the row immediately before context menus or copy actions run.
/// </summary>
public static class DataListSelection
{
    public static readonly AttachedProperty<bool> SelectOnPointerPressProperty =
        AvaloniaProperty.RegisterAttached<ListBox, bool>("SelectOnPointerPress", typeof(DataListSelection));

    static DataListSelection()
    {
        SelectOnPointerPressProperty.Changed.AddClassHandler<ListBox>(OnSelectOnPointerPressChanged);
    }

    public static bool GetSelectOnPointerPress(ListBox listBox)
    {
        ArgumentNullException.ThrowIfNull(listBox);
        return listBox.GetValue(SelectOnPointerPressProperty);
    }

    public static void SetSelectOnPointerPress(ListBox listBox, bool value)
    {
        ArgumentNullException.ThrowIfNull(listBox);
        listBox.SetValue(SelectOnPointerPressProperty, value);
    }

    /// <summary>
    /// Selects the <see cref="ListBoxItem"/> containing <paramref name="visual"/> in its owning
    /// <see cref="ListBox"/>, returning true when an item was found.
    /// </summary>
    internal static bool SelectContainingListItem(Visual? visual, bool focusItem = false)
    {
        var item = FindAncestor<ListBoxItem>(visual);
        if (item is null)
        {
            return false;
        }

        var list = FindAncestor<ListBox>(item.GetVisualParent());
        if (list is null || item.DataContext is null)
        {
            return false;
        }

        if (!ReferenceEquals(list.SelectedItem, item.DataContext))
        {
            list.SelectedItem = item.DataContext;
        }

        if (focusItem && item.Focusable)
        {
            item.Focus();
        }

        return true;
    }

    private static void OnSelectOnPointerPressChanged(ListBox listBox, AvaloniaPropertyChangedEventArgs args)
    {
        if (args.NewValue is true)
        {
            listBox.AddHandler(InputElement.PointerPressedEvent, OnListPointerPressed, RoutingStrategies.Tunnel, handledEventsToo: true);
            listBox.AddHandler(Control.ContextRequestedEvent, OnListContextRequested, RoutingStrategies.Tunnel, handledEventsToo: true);
        }
        else
        {
            listBox.RemoveHandler(InputElement.PointerPressedEvent, OnListPointerPressed);
            listBox.RemoveHandler(Control.ContextRequestedEvent, OnListContextRequested);
        }
    }

    private static void OnListPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (sender is not Visual root)
        {
            return;
        }

        var properties = e.GetCurrentPoint(root).Properties;
        if (!properties.IsLeftButtonPressed && !properties.IsRightButtonPressed)
        {
            return;
        }

        SelectContainingListItem(e.Source as Visual, focusItem: properties.IsRightButtonPressed);
    }

    private static void OnListContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        SelectContainingListItem(e.Source as Visual, focusItem: true);
    }

    private static T? FindAncestor<T>(Visual? visual) where T : Visual
    {
        while (visual is not null)
        {
            if (visual is T match)
            {
                return match;
            }

            visual = visual.GetVisualParent();
        }

        return null;
    }
}
