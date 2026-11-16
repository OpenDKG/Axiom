// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;

namespace Axiom.UI.Avalonia.Controls;

/// <summary>
/// Attached behavior for data <see cref="ListBox"/> controls so clicking any cell (including on
/// right-click, padding, or nested visuals) selects the row immediately before context menus or
/// copy actions run, and grouped lists can share a single ViewModel selection without clearing
/// each other.
/// </summary>
public static class DataListSelection
{
    public static readonly AttachedProperty<bool> SelectOnPointerPressProperty =
        AvaloniaProperty.RegisterAttached<ListBox, bool>("SelectOnPointerPress", typeof(DataListSelection));

    public static readonly AttachedProperty<object?> SharedSelectedItemProperty =
        AvaloniaProperty.RegisterAttached<ListBox, object?>(
            "SharedSelectedItem",
            typeof(DataListSelection),
            defaultBindingMode: BindingMode.TwoWay);

    private static readonly ConditionalWeakTable<ListBox, SyncState> SharedSyncStates = new();

    static DataListSelection()
    {
        SelectOnPointerPressProperty.Changed.AddClassHandler<ListBox>(OnSelectOnPointerPressChanged);
        SharedSelectedItemProperty.Changed.AddClassHandler<ListBox>(OnSharedSelectedItemChanged);
        global::Avalonia.Controls.Primitives.SelectingItemsControl.SelectionChangedEvent.AddClassHandler<ListBox>(
            OnSharedListSelectionChanged);
        Control.LoadedEvent.AddClassHandler<ListBox>(OnSharedListLoaded);
    }

    public static object? GetSharedSelectedItem(ListBox listBox)
    {
        ArgumentNullException.ThrowIfNull(listBox);
        return listBox.GetValue(SharedSelectedItemProperty);
    }

    public static void SetSharedSelectedItem(ListBox listBox, object? value)
    {
        ArgumentNullException.ThrowIfNull(listBox);
        listBox.SetValue(SharedSelectedItemProperty, value);
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

        if (focusItem && item.Focusable && FindAncestor<Button>(visual) is null)
        {
            item.Focus();
        }

        return true;
    }

    private static bool UsesSharedSelection(ListBox listBox) =>
        listBox.IsSet(SharedSelectedItemProperty);

    private static SyncState GetSyncState(ListBox listBox) =>
        SharedSyncStates.GetOrCreateValue(listBox);

    private static void OnSharedSelectedItemChanged(ListBox listBox, AvaloniaPropertyChangedEventArgs args)
    {
        ApplySharedSelectionToList(listBox, GetSyncState(listBox), args.NewValue);
    }

    private static void OnSharedListLoaded(ListBox listBox, RoutedEventArgs e)
    {
        if (UsesSharedSelection(listBox))
        {
            ApplySharedSelectionToList(listBox, GetSyncState(listBox), GetSharedSelectedItem(listBox));
        }
    }

    private static void OnSharedListSelectionChanged(ListBox listBox, SelectionChangedEventArgs e)
    {
        if (!UsesSharedSelection(listBox))
        {
            return;
        }

        var state = GetSyncState(listBox);
        if (state.IsApplying)
        {
            return;
        }

        if (e.AddedItems.Count > 0 && listBox.SelectedItem is { } selected)
        {
            listBox.SetCurrentValue(SharedSelectedItemProperty, selected);
        }
    }

    private static void ApplySharedSelectionToList(ListBox listBox, SyncState state, object? target)
    {
        if (state.IsApplying)
        {
            return;
        }

        state.IsApplying = true;
        try
        {
            object? match = null;
            if (target is not null)
            {
                foreach (var item in listBox.Items)
                {
                    if (ReferenceEquals(item, target) || Equals(item, target))
                    {
                        match = item;
                        break;
                    }
                }
            }

            if (!ReferenceEquals(listBox.SelectedItem, match))
            {
                listBox.SelectedItem = match;
            }
        }
        finally
        {
            state.IsApplying = false;
        }
    }

    private sealed class SyncState
    {
        public bool IsApplying;
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

        SelectContainingListItem(e.Source as Visual, focusItem: true);
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
