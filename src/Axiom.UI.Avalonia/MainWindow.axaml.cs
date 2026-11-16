// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.VisualTree;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

public partial class MainWindow : Window
{
    private const string WindowBrushKey = "Axiom.Window";
    private const double SidebarExpandedWidth = 252;
    private const double MiniWindowMinWidth = 900;
    private const double MiniWindowMinHeight = 560;
    private const double MiniWindowDefaultWidth = 1040;
    private const double MiniWindowDefaultHeight = 660;
    private const double FullWindowMinWidth = 900;
    private const double FullWindowMinHeight = 600;

    private IVisualEffectsService? _effects;
    private ShellViewModel? _shell;
    private bool _applyingBackdrop;
    private bool _isMiniWindowLayout;
    private Size _expandedWindowSize = new(1460, 900);

    public MainWindow()
    {
        InitializeComponent();
        UpdateCaptionGlyph();
        AddHandler(PointerPressedEvent, OnWindowPointerPressed, RoutingStrategies.Tunnel, handledEventsToo: true);
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);

        if (DataContext is ShellViewModel shell)
        {
            _shell = shell;
            _shell.PropertyChanged += OnShellPropertyChanged;
            _effects = shell.VisualEffects;
            _effects.Changed += OnVisualEffectsChanged;
            ApplyWindowLayoutForMode(shell.IsMiniMode);
        }

        if (Application.Current is { } application)
        {
            application.ActualThemeVariantChanged += OnThemeVariantChanged;
        }

        ApplyBackdrop();
    }

    protected override void OnClosed(EventArgs e)
    {
        if (_shell is not null)
        {
            _shell.PropertyChanged -= OnShellPropertyChanged;
            _shell = null;
        }

        if (_effects is not null)
        {
            _effects.Changed -= OnVisualEffectsChanged;
            _effects = null;
        }

        if (Application.Current is { } application)
        {
            application.ActualThemeVariantChanged -= OnThemeVariantChanged;
        }

        base.OnClosed(e);
    }

    private void OnShellPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_shell is not null && (e.PropertyName is null or nameof(ShellViewModel.IsMiniMode)))
        {
            ApplyWindowLayoutForMode(_shell.IsMiniMode);
        }
    }

    private void ApplyWindowLayoutForMode(bool mini)
    {
        if (RootLayout?.ColumnDefinitions.Count >= 2)
        {
            RootLayout.ColumnDefinitions[0].Width = mini
                ? new GridLength(0)
                : new GridLength(SidebarExpandedWidth);
        }

        if (mini == _isMiniWindowLayout)
        {
            return;
        }

        _isMiniWindowLayout = mini;
        if (mini)
        {
            if (WindowState == WindowState.Maximized)
            {
                WindowState = WindowState.Normal;
            }

            if (Width >= FullWindowMinWidth && Height >= FullWindowMinHeight)
            {
                _expandedWindowSize = new Size(Width, Height);
            }

            MinWidth = MiniWindowMinWidth;
            MinHeight = MiniWindowMinHeight;
            Width = MiniWindowDefaultWidth;
            Height = MiniWindowDefaultHeight;
        }
        else
        {
            MinWidth = FullWindowMinWidth;
            MinHeight = FullWindowMinHeight;
            Width = Math.Max(FullWindowMinWidth, _expandedWindowSize.Width);
            Height = Math.Max(FullWindowMinHeight, _expandedWindowSize.Height);
        }
    }

    private void OnVisualEffectsChanged(object? sender, EventArgs e) => ApplyBackdrop();

    private void OnThemeVariantChanged(object? sender, EventArgs e) => ApplyBackdrop();

    /// <summary>
    /// Requests the strongest backdrop the platform supports for the active theme. The window never
    /// assumes success: <see cref="TopLevel.ActualTransparencyLevel"/> decides the reported status.
    /// </summary>
    private void ApplyBackdrop()
    {
        if (_applyingBackdrop)
        {
            return;
        }

        _applyingBackdrop = true;
        try
        {
            var glass = IsGlassTheme();
            var mode = _effects?.Current ?? VisualEffects.Auto;

            TransparencyLevelHint = !glass || mode == VisualEffects.Off
                ? [WindowTransparencyLevel.None]
                : mode == VisualEffects.Reduced
                    ? [WindowTransparencyLevel.Blur, WindowTransparencyLevel.None]
                    : [WindowTransparencyLevel.AcrylicBlur, WindowTransparencyLevel.Mica,
                       WindowTransparencyLevel.Blur, WindowTransparencyLevel.None];

            UpdateBackdropTint(glass);
            ReportBackdrop(glass);
        }
        finally
        {
            _applyingBackdrop = false;
        }
    }

    /// <summary>
    /// Keeps the glass surface translucent only when a native backdrop is really composited. Without
    /// one, the same theme falls back to an opaque graphite/quartz gradient so the desktop does not
    /// show through unblurred while preserving dimensional lighting.
    /// </summary>
    private void UpdateBackdropTint(bool glass)
    {
        if (!glass || IsNativeBackdrop(ActualTransparencyLevel))
        {
            Resources.Remove(WindowBrushKey);
            return;
        }

        Resources[WindowBrushKey] = IsGlassLight()
            ? new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Color.Parse("#EDF2F8"), 0),
                    new GradientStop(Color.Parse("#E3E9F2"), 0.55),
                    new GradientStop(Color.Parse("#D6DFE9"), 1)
                }
            }
            : new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Color.Parse("#06080D"), 0),
                    new GradientStop(Color.Parse("#0B0F17"), 0.55),
                    new GradientStop(Color.Parse("#04060A"), 1)
                }
            };
    }

    private void ReportBackdrop(bool glass)
    {
        if (_effects is null)
        {
            return;
        }

        var level = ActualTransparencyLevel;
        var status = !glass
            ? "classic theme, solid surfaces"
            : IsNativeBackdrop(level)
                ? $"{level} (native backdrop active)"
                : "simulated glass, native backdrop unavailable";

        _effects.ReportBackdrop(status);
    }

    private bool IsGlassTheme() =>
        ActualThemeVariant.Equals(AxiomThemeVariants.GlassDark)
        || ActualThemeVariant.Equals(AxiomThemeVariants.GlassLight);

    private bool IsGlassLight() => ActualThemeVariant.Equals(AxiomThemeVariants.GlassLight);

    private static bool IsNativeBackdrop(WindowTransparencyLevel level) =>
        level == WindowTransparencyLevel.AcrylicBlur
        || level == WindowTransparencyLevel.Mica
        || level == WindowTransparencyLevel.Blur;

    private void OnWindowPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        var properties = e.GetCurrentPoint(this).Properties;
        if (!properties.IsLeftButtonPressed && !properties.IsRightButtonPressed)
        {
            return;
        }

        // Selectable text handles the pointer before the row does. Keep row selection working when
        // the user left-clicks or right-clicks text inside a ListBox item.
        Controls.DataListSelection.SelectContainingListItem(
            e.Source as Visual,
            focusItem: true);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == WindowStateProperty)
        {
            UpdateCaptionGlyph();
        }

        if (change.Property == ActualTransparencyLevelProperty && !_applyingBackdrop)
        {
            var glass = IsGlassTheme();
            UpdateBackdropTint(glass);
            ReportBackdrop(glass);
        }
    }

    private void OnMinimizeClicked(object? sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void OnUpdateClicked(object? sender, RoutedEventArgs e)
    {
        AlertsPopup.IsOpen = false;
        UpdatePopup.IsOpen = !UpdatePopup.IsOpen;
    }

    private void OnUpdateDownloadClicked(object? sender, RoutedEventArgs e) =>
        UpdatePopup.IsOpen = false;

    private void OnUpdateDismissClicked(object? sender, RoutedEventArgs e) =>
        UpdatePopup.IsOpen = false;

    private void OnAlertsClicked(object? sender, RoutedEventArgs e)
    {
        UpdatePopup.IsOpen = false;
        AlertsPopup.IsOpen = !AlertsPopup.IsOpen;
    }

    private void OnAlertItemClicked(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: AlertRecord alert } && DataContext is ShellViewModel shell)
        {
            shell.OpenAlert(alert);
        }

        AlertsPopup.IsOpen = false;
    }

    private void OnMaximizeClicked(object? sender, RoutedEventArgs e) => ToggleMaximize();

    private void OnCloseClicked(object? sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize() =>
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    private void UpdateCaptionGlyph()
    {
        if (MaximizeButton is null)
        {
            return;
        }

        MaximizeButton.Content = WindowState == WindowState.Maximized ? "\uE923" : "\uE922";
        ToolTip.SetTip(
            MaximizeButton,
            WindowState == WindowState.Maximized ? "Restore" : "Maximize");
    }
}
