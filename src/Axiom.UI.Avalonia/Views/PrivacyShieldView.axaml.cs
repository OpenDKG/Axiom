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

    public PrivacyShieldView()
    {
        InitializeComponent();
        BlockedHistoryScroll.ScrollChanged += (_, _) => _historyOffset = BlockedHistoryScroll.Offset.Y;
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_viewModel is not null)
        {
            _viewModel.BlockedHistoryGroups.CollectionChanged -= OnBlockedHistoryChanged;
        }

        _viewModel = DataContext as PrivacyShieldPageViewModel;
        if (_viewModel is not null)
        {
            _viewModel.BlockedHistoryGroups.CollectionChanged += OnBlockedHistoryChanged;
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
