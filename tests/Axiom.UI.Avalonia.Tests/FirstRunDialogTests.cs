// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Avalonia.Threading;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The onboarding dialog must fit small screens, stay resizable, and never offer automatic Blackbox
/// sharing unless Blackbox itself is selected.
/// </summary>
public sealed class FirstRunDialogTests
{
    [Fact]
    public async Task Dialog_is_resizable_and_fits_a_small_working_area()
    {
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var dialog = new FirstRunDialog(new UnsupportedApiKeyProtector());
            try
            {
                Assert.True(dialog.CanResize);
                Assert.InRange(dialog.MinWidth, 1, dialog.Width);
                Assert.InRange(dialog.MinHeight, 1, dialog.Height);
                // A 1280x720 screen at 150% offers 853x480 DIP; the dialog must clamp to it.
                var (width, height, _) = MainWindow.FitToWorkingArea(
                    dialog.Width, dialog.Height, dialog.MinWidth, dialog.MinHeight,
                    new global::Avalonia.PixelRect(0, 0, 1280, 720), 1.5);
                Assert.InRange(width, dialog.MinWidth, 1280 / 1.5 + 1);
                Assert.InRange(height, dialog.MinHeight, 720 / 1.5 + 1);
            }
            finally
            {
                dialog.Close();
            }

            return Task.CompletedTask;
        });
    }

    [Fact]
    public async Task Automatic_sharing_requires_blackbox_selection()
    {
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var dialog = new FirstRunDialog(new UnsupportedApiKeyProtector());
            try
            {
                Assert.False(dialog.AutomaticSharingOption.IsEnabled);
                dialog.AutomaticSharingOption.IsChecked = true;
                Assert.False(dialog.BlackboxOption.IsChecked == true);

                dialog.BlackboxOption.IsChecked = true;
                Assert.True(dialog.AutomaticSharingOption.IsEnabled);

                dialog.AutomaticSharingOption.IsChecked = true;
                dialog.BlackboxOption.IsChecked = false;
                Assert.False(dialog.AutomaticSharingOption.IsEnabled);
                Assert.False(dialog.AutomaticSharingOption.IsChecked == true);
            }
            finally
            {
                dialog.Close();
            }

            return Task.CompletedTask;
        });
    }
}
