// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Specialized;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;

namespace Axiom.UI.Avalonia.Views;

public partial class PrivacyShieldView : UserControl
{
    private PrivacyShieldPageViewModel? _viewModel;
    private double _historyOffset;
    private bool _restorePending;
    private bool _attached;

    public PrivacyShieldView()
    {
        InitializeComponent();
        BlockedHistoryScroll.ScrollChanged += (_, _) => _historyOffset = BlockedHistoryScroll.Offset.Y;
        DataContextChanged += OnDataContextChanged;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        AttachViewModel();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _attached = false;
        DetachViewModel();
        base.OnDetachedFromVisualTree(e);
    }

    private void OnDataContextChanged(object? sender, EventArgs e) => AttachViewModel();

    private void AttachViewModel()
    {
        DetachViewModel();
        if (!_attached)
        {
            return;
        }

        _viewModel = DataContext as PrivacyShieldPageViewModel;
        if (_viewModel is not null)
        {
            _viewModel.BlockedHistoryGroups.CollectionChanged += OnBlockedHistoryChanged;
        }
    }

    private void DetachViewModel()
    {
        if (_viewModel is not null)
        {
            _viewModel.BlockedHistoryGroups.CollectionChanged -= OnBlockedHistoryChanged;
            _viewModel = null;
        }
    }

    /// <summary>
    /// The retained history is rebuilt when a blocked query arrives. Without this, the list jumps
    /// back to the top while the user is reading an expanded application.
    /// </summary>
    private void OnBlockedHistoryChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (_restorePending)
        {
            return;
        }

        _restorePending = true;
        Dispatcher.UIThread.Post(
            () =>
            {
                _restorePending = false;
                BlockedHistoryScroll.Offset = new Vector(BlockedHistoryScroll.Offset.X, _historyOffset);
            },
            DispatcherPriority.Loaded);
    }
}
