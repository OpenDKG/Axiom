// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Modules;
using Xunit;

namespace Netpetra.Contracts.Tests;

public sealed class BoundedHistoryTests
{
    [Fact]
    public void Adding_more_than_the_capacity_keeps_the_newest_items()
    {
        var history = new BoundedHistory<int>(30);

        for (var value = 0; value <= 30; value++)
        {
            history.Add(value);
        }

        Assert.Equal(30, history.Count);
        Assert.Equal(30, history.Capacity);
        Assert.Equal(1, history.Items[0]);
        Assert.Equal(30, history.Items[^1]);
    }

    [Fact]
    public void Invalid_capacity_is_rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedHistory<int>(0));
    }
}
