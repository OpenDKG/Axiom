// SPDX-License-Identifier: GPL-3.0-or-later
using System.Threading;
using Avalonia.Media;
using Avalonia.Threading;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// Regression for the test-host crash "The calling thread cannot access this object because a
/// different thread owns it" during headless set-up: the UI dispatcher must belong to the
/// headless thread before any test runs, even one that builds Avalonia objects on a worker thread.
/// </summary>
public sealed class HeadlessUiThreadOwnershipTests
{
    [Fact]
    public void Ui_dispatcher_belongs_to_the_headless_thread_before_a_worker_creates_avalonia_objects()
    {
        // Runs on an xUnit worker thread and touches nothing from TestAppBuilder first: the
        // framework must already have set the headless application up.
        var brush = new SolidColorBrush(Colors.Red);

        Assert.NotNull(TestAppBuilder.UiThread);
        Assert.NotSame(Thread.CurrentThread, TestAppBuilder.UiThread);
        Assert.Same(TestAppBuilder.UiThread, Dispatcher.UIThread.Thread);
        Assert.False(Dispatcher.UIThread.CheckAccess());
        Assert.NotSame(Dispatcher.UIThread, brush.Dispatcher);
    }

    [Fact]
    public void Ui_work_runs_on_the_headless_thread()
    {
        Thread? ranOn = null;

        TestAppBuilder.RunOnUiThread(() => ranOn = Thread.CurrentThread);

        Assert.Same(TestAppBuilder.UiThread, ranOn);
        Assert.Same(Dispatcher.UIThread.Thread, ranOn);
    }
}
