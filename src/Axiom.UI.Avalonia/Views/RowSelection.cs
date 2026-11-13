// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.VisualTree;

namespace Axiom.UI.Avalonia.Views;

/// <summary>
/// Selects the row a pointer press landed on. Selectable text cells consume the press and would
/// otherwise leave the ListBox selection on the previous row (or none), which also made the copy
/// context-menu commands act on nothing.
/// </summary>
internal static class RowSelection
{
    public static void SelectRow(Control row)
    {
        if (row.DataContext is null)
        {
            return;
        }

        var list = row.FindAncestorOfType<ListBox>();
        if (list is null)
        {
            return;
        }

        if (list.ItemsSource is System.Collections.IEnumerable items)
        {
            foreach (var item in items)
            {
                if (ReferenceEquals(item, row.DataContext))
                {
                    list.SelectedItem = item;
                    return;
                }
            }
        }

        list.SelectedItem = row.DataContext;
    }
}
