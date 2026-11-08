// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Protection;
using Axiom.Core.Protection;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class PendingAppLedgerTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 8, 20, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Pending_app_stays_after_its_connection_ends()
    {
        var detected = Pending("app.exe", Now.AddSeconds(-5));
        var first = PendingAppLedger.Merge([], [], [detected], [], Now);

        var second = PendingAppLedger.Merge(first.Pending, first.Dismissals, [], [], Now.AddMinutes(1));

        var item = Assert.Single(second.Pending);
        Assert.False(item.IsConnected);
        Assert.Equal("app.exe", item.AppName);
    }

    [Fact]
    public void Dismiss_hides_the_app_until_a_new_connection_appears()
    {
        var detected = Pending("app.exe", Now.AddSeconds(-5));
        var first = PendingAppLedger.Merge([], [], [detected], [], Now);

        var dismissed = PendingAppLedger.Merge(
            first.Pending,
            [new ProtectionDismissal { AppPath = @"C:\Tools\app.exe", DismissedUtc = Now }],
            [],
            [],
            Now.AddSeconds(1));

        Assert.Empty(dismissed.Pending);
        Assert.Single(dismissed.Dismissals);

        var oldConnection = Pending("app.exe", Now.AddSeconds(-5));
        var stillHidden = PendingAppLedger.Merge(
            dismissed.Pending,
            dismissed.Dismissals,
            [oldConnection],
            [],
            Now.AddSeconds(2));
        Assert.Empty(stillHidden.Pending);

        var newConnection = Pending("app.exe", Now.AddSeconds(3));
        var reappeared = PendingAppLedger.Merge(
            dismissed.Pending,
            dismissed.Dismissals,
            [newConnection],
            [],
            Now.AddSeconds(4));
        Assert.Single(reappeared.Pending);
        Assert.Empty(reappeared.Dismissals);
    }

    [Fact]
    public void Decision_removes_a_pending_app()
    {
        var detected = Pending("app.exe", Now.AddSeconds(-5));
        var first = PendingAppLedger.Merge([], [], [detected], [], Now);
        var decision = new ProtectionDecision
        {
            AppPath = @"C:\Tools\app.exe",
            AppName = "app.exe",
            Action = ProtectionDecisionAction.Allow,
            DecidedUtc = Now,
        };

        var decided = PendingAppLedger.Merge(first.Pending, first.Dismissals, [detected], [decision], Now);

        Assert.Empty(decided.Pending);
    }

    private static ProtectionPendingApp Pending(string name, DateTimeOffset firstObserved) => new()
    {
        AppPath = @"C:\Tools\" + name,
        AppName = name,
        SocketCount = 1,
        FirstObservedUtc = firstObserved,
        IsConnected = true,
        LastSeenUtc = firstObserved,
        LatestConnectionFirstObservedUtc = firstObserved,
    };
}
