// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Updates observable lists in place so background refreshes keep existing row containers and
/// active selections alive instead of rebuilding every item via <c>Clear()</c>.
/// </summary>
internal static class CollectionSync
{
    public static void SyncInPlace<T>(
        ObservableCollection<T> target,
        IReadOnlyList<T> desired,
        IEqualityComparer<T>? comparer = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(desired);

        if (desired.Count == 0)
        {
            if (target.Count > 0)
            {
                target.Clear();
            }

            return;
        }

        comparer ??= EqualityComparer<T>.Default;
        var wanted = new HashSet<T>(desired, comparer);
        for (var index = target.Count - 1; index >= 0; index--)
        {
            if (!wanted.Contains(target[index]))
            {
                target.RemoveAt(index);
            }
        }

        for (var index = 0; index < desired.Count; index++)
        {
            var item = desired[index];
            var current = IndexOf(target, item, comparer, index);
            if (current < 0)
            {
                target.Insert(index, item);
            }
            else if (current != index)
            {
                target.Move(current, index);
            }
        }
    }

    private static int IndexOf<T>(
        ObservableCollection<T> list,
        T item,
        IEqualityComparer<T> comparer,
        int startIndex)
    {
        for (var index = startIndex; index < list.Count; index++)
        {
            if (comparer.Equals(list[index], item))
            {
                return index;
            }
        }

        for (var index = 0; index < startIndex && index < list.Count; index++)
        {
            if (comparer.Equals(list[index], item))
            {
                return index;
            }
        }

        return -1;
    }
}
