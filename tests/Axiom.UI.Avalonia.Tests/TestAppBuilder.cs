// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Headless;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// One headless Avalonia application per test process, owned by one dedicated UI thread.
/// </summary>
/// <remarks>
/// Avalonia 12 makes the first <see cref="Dispatcher"/> created in the process the UI-thread
/// dispatcher, and every <see cref="AvaloniaObject"/> constructor (a view model's brush, for
/// example) or <c>Dispatcher.UIThread</c> access creates one for the calling thread. If a test
/// running on an xUnit worker thread did that before the headless thread started, the worker
/// owned <c>Dispatcher.UIThread</c> and the headless platform set-up on this thread crashed the
/// test host ("The calling thread cannot access this object because a different thread owns
/// it"); set-up running alongside worker-thread tests also raced Avalonia's unsynchronised
/// routed-event registry. <see cref="HeadlessTestFramework"/> therefore starts this thread and
/// completes the set-up before any test runs.
/// </remarks>
public static class TestAppBuilder
{
    private static readonly object Gate = new();
    private static bool _initialized;
    private static Thread? _uiThread;
    private static readonly TaskCompletionSource UiReady = new();

    /// <summary>The headless UI thread, once <see cref="StartUiThread"/> has run.</summary>
    public static Thread? UiThread => _uiThread;

    private static void EnsureInitialized()
    {
        lock (Gate)
        {
            if (_initialized)
            {
                return;
            }

            // Avalonia resolves "avares://Axiom.UI.Avalonia/..." to the shortest LOADED assembly
            // whose name starts with "Axiom.UI.Avalonia" and caches the answer. Before any test
            // has touched a product type that is this test assembly, which has no compiled theme
            // XAML ("No precompiled XAML found"), so load the UI assembly first.
            GC.KeepAlive(typeof(global::Axiom.UI.Avalonia.ShellViewModel).Assembly);

            AppBuilder.Configure<TestApp>()
                .UseHeadless(new AvaloniaHeadlessPlatformOptions())
                .SetupWithoutStarting();
            _initialized = true;
        }
    }

    /// <summary>
    /// Starts the headless UI thread (once) and blocks until the Avalonia application is set up
    /// on it, so that thread owns <c>Dispatcher.UIThread</c>. Rethrows a set-up failure.
    /// </summary>
    public static void StartUiThread()
    {
        lock (Gate)
        {
            if (_uiThread is null)
            {
                _uiThread = new Thread(() =>
                {
                    try
                    {
                        EnsureInitialized();
                    }
                    catch (Exception ex)
                    {
                        UiReady.TrySetException(ex);
                        return;
                    }

                    UiReady.TrySetResult();
                    Dispatcher.UIThread.MainLoop(CancellationToken.None);
                })
                {
                    IsBackground = true,
                    Name = "Avalonia Headless UI Test Thread",
                };
                if (OperatingSystem.IsWindows())
                {
                    _uiThread.SetApartmentState(ApartmentState.STA);
                }

                _uiThread.Start();
            }
        }

        UiReady.Task.GetAwaiter().GetResult();
    }

    /// <summary>
    /// Runs an async test body on the headless UI thread. Avalonia objects keep thread affinity,
    /// and dispatcher-posted work runs there too, so tests that touch view models directly must
    /// not race that thread from an xUnit worker.
    /// </summary>
    public static Task RunOnUiThreadAsync(Func<Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        StartUiThread();
        return Dispatcher.UIThread.InvokeAsync(action);
    }

    public static void RunOnUiThread(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);

        StartUiThread();
        if (Dispatcher.UIThread.CheckAccess())
        {
            action();
            return;
        }

        Dispatcher.UIThread.Invoke(action);
    }

    private sealed class TestApp : Application
    {
        public override void Initialize()
        {
            Resources.MergedDictionaries.Add(new global::Avalonia.Markup.Xaml.Styling.ResourceInclude((Uri?)null)
            {
                Source = new Uri("avares://Axiom.UI.Avalonia/Themes/AxiomPalette.axaml"),
            });
            Styles.Add(new FluentTheme());
            Styles.Add(new global::Avalonia.Markup.Xaml.Styling.StyleInclude((Uri?)null)
            {
                Source = new Uri("avares://Axiom.UI.Avalonia/Themes/AxiomControls.axaml"),
            });
        }
    }
}
