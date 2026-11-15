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
/// One headless Avalonia application per test process. It is initialized lazily so the pure
/// view-model tests do not pay for a render stack.
/// </summary>
public static class TestAppBuilder
{
    private static readonly object Gate = new();
    private static bool _initialized;
    private static Thread? _uiThread;
    private static readonly TaskCompletionSource UiReady = new();

    public static void EnsureInitialized()
    {
        lock (Gate)
        {
            if (_initialized)
            {
                return;
            }

            AppBuilder.Configure<TestApp>()
                .UseHeadless(new AvaloniaHeadlessPlatformOptions())
                .SetupWithoutStarting();
            _initialized = true;
        }
    }

    public static void RunOnUiThread(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);

        lock (Gate)
        {
            if (_uiThread is null)
            {
                _uiThread = new Thread(() =>
                {
                    EnsureInitialized();
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
