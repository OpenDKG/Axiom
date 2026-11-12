// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Headless;
using Avalonia.Themes.Fluent;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// One headless Avalonia application per test process. It is initialized lazily so the pure
/// view-model tests do not pay for a render stack.
/// </summary>
public static class TestAppBuilder
{
    private static readonly object Gate = new();
    private static bool _initialized;

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
