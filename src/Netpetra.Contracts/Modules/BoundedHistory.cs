// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.Contracts.Modules;

/// <summary>Fixed-size FIFO history used by the optional-module activity strip.</summary>
public sealed class BoundedHistory<T>
{
    private readonly int _capacity;

    private readonly Queue<T> _items = new();

    public BoundedHistory(int capacity)
    {
        if (capacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity), "Capacity must be positive.");
        }

        _capacity = capacity;
    }

    public int Capacity => _capacity;

    public int Count => _items.Count;

    public IReadOnlyList<T> Items => _items.ToArray();

    public void Add(T item)
    {
        _items.Enqueue(item);
        while (_items.Count > _capacity)
        {
            _items.Dequeue();
        }
    }
}
