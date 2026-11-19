// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;

namespace Axiom.UI.Avalonia.Views;

public partial class FirewallView : UserControl
{
    private FirewallPageViewModel? _page;
    private bool _attached;

    public FirewallView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        AttachViewModel();
    }

    private void OnDataContextChanged(object? sender, EventArgs e) => AttachViewModel();

    private void AttachViewModel()
    {
        DetachViewModel();
        if (!_attached)
        {
            return;
        }

        _page = DataContext as FirewallPageViewModel;
        if (_page is not null)
        {
            _page.AlertFocusRequested += OnAlertFocusRequested;
        }
    }

    private void DetachViewModel()
    {
        if (_page is not null)
        {
            _page.AlertFocusRequested -= OnAlertFocusRequested;
            _page = null;
        }
    }

    private void OnAlertFocusRequested(object? sender, EventArgs e) =>
        Dispatcher.UIThread.Post(
            () => PageScroll.Offset = new Vector(0, 0),
            DispatcherPriority.Background);

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _attached = false;
        DetachViewModel();
        base.OnDetachedFromVisualTree(e);
    }
}
