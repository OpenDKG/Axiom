// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia.Controls;

namespace Axiom.UI.Avalonia.Views;

public partial class AiAnalystView : UserControl
{
    private INotifyPropertyChanged? _viewModel;

    public AiAnalystView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => AttachViewModel();
    }

    private void AttachViewModel()
    {
        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        _viewModel = DataContext as INotifyPropertyChanged;
        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;
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
