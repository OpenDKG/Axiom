// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;

namespace Axiom.UI.Avalonia.Views;

public partial class AiAnalystView : UserControl
{
    private INotifyPropertyChanged? _viewModel;
    private bool _attached;

    public AiAnalystView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => AttachViewModel();
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

    private void AttachViewModel()
    {
        DetachViewModel();
        if (!_attached)
        {
            return;
        }

        _viewModel = DataContext as INotifyPropertyChanged;
        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void DetachViewModel()
    {
        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _viewModel = null;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.Equals(e.PropertyName, nameof(AiAnalystPageViewModel.SelectedFinding), StringComparison.Ordinal))
        {
            ResultScroll.Offset = default;
        }
    }
}
