// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;

namespace Axiom.UI.Avalonia.Views;

public partial class FirewallView : UserControl
{
    private FirewallPageViewModel? _page;

    public FirewallView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_page is not null)
        {
            _page.AlertFocusRequested -= OnAlertFocusRequested;
        }

        _page = DataContext as FirewallPageViewModel;
        if (_page is not null)
        {
            _page.AlertFocusRequested += OnAlertFocusRequested;
        }
    }

    private void OnAlertFocusRequested(object? sender, EventArgs e) =>
        Dispatcher.UIThread.Post(
            () => PageScroll.Offset = new Vector(0, 0),
            DispatcherPriority.Background);

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnDetachedFromVisualTree(e);
        if (_page is not null)
        {
            _page.AlertFocusRequested -= OnAlertFocusRequested;
            _page = null;
        }
    }
}
