// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Styling;

namespace Axiom.UI.Avalonia.Views;

public partial class AgentsView : UserControl
{
    public AgentsView()
    {
        InitializeComponent();
        ActualThemeVariantChanged += (_, _) => UpdateLogoShadow();
        UpdateLogoShadow();
    }

    private void UpdateLogoShadow() =>
        Classes.Set("light-logo-shadow",
            ActualThemeVariant == ThemeVariant.Light ||
            ActualThemeVariant?.InheritVariant == ThemeVariant.Light);
}
