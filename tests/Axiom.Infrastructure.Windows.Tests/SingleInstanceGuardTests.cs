// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Threading;
using Axiom.Infrastructure.Windows;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class SingleInstanceGuardTests
{
    [Fact]
    public void Second_acquire_signals_first_instance_and_returns_null_until_released()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var mutexName = $@"Local\Axiom.Test.SingleInstance.{suffix}";
        var eventName = $@"Local\Axiom.Test.Show.{suffix}";

        using var signalled = new ManualResetEventSlim(false);
        using (var first = SingleInstanceGuard.AcquireOrSignalExisting(mutexName, eventName))
        {
            Assert.NotNull(first);
            first!.StartListening(() => signalled.Set());

            var second = SingleInstanceGuard.AcquireOrSignalExisting(mutexName, eventName);
            Assert.Null(second);
            Assert.True(signalled.Wait(TimeSpan.FromSeconds(2)));
        }

        using var afterRelease = SingleInstanceGuard.AcquireOrSignalExisting(mutexName, eventName);
        Assert.NotNull(afterRelease);
    }
}
