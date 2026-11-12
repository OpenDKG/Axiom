// SPDX-License-Identifier: GPL-3.0-or-later
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

    private IVisualEffectsService? _effects;
    private bool _applyingBackdrop;

    public MainWindow()
    {
        InitializeComponent();
        if (!OperatingSystem.IsWindows())
        {
            UseNativeCaption();
        }

        UpdateCaptionGlyph();
        AddHandler(PointerPressedEvent, OnWindowPointerPressed, RoutingStrategies.Tunnel, handledEventsToo: true);
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);

        if (DataContext is ShellViewModel shell)
        {
            _effects = shell.VisualEffects;
            _effects.Changed += OnVisualEffectsChanged;
        }

        if (Application.Current is { } application)
        {
            application.ActualThemeVariantChanged += OnThemeVariantChanged;
        }

        ApplyBackdrop();
    }

    protected override void OnClosed(EventArgs e)
    {
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
    /// one, the same theme falls back to an opaque graphite/pearl base so the desktop does not show
    /// through unblurred.
    /// </summary>
    private void UpdateBackdropTint(bool glass)
    {
        if (!glass || IsNativeBackdrop(ActualTransparencyLevel))
        {
            Resources.Remove(WindowBrushKey);
            return;
        }

        var fallback = IsGlassLight()
            ? Color.Parse("#EDF3F8")
            : Color.Parse("#0B1019");
        Resources[WindowBrushKey] = new SolidColorBrush(fallback);
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
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        // Selectable text handles the pointer before the row does. Keep row selection working when
        // the user clicks text inside a ListBox item, while still allowing the text selection.
        SelectContainingListItem(e.Source as Visual);
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

    /// <summary>
    /// The drawn caption buttons use Segoe MDL2 Assets and Windows placement. Elsewhere (macOS)
    /// the native window buttons are kept over the extended title bar, the title content makes
    /// room for them, and the bell uses a vector icon.
    /// </summary>
    private void UseNativeCaption()
    {
        WindowDecorations = WindowDecorations.Full;
        MinimizeButton.IsVisible = false;
        MaximizeButton.IsVisible = false;
        CloseButton.IsVisible = false;
        BellGlyph.IsVisible = false;
        BellIcon.IsVisible = true;
        if (OperatingSystem.IsMacOS())
        {
            TitleContent.Margin = new Thickness(70, 0, 0, 0);
        }
    }

    private void OnMinimizeClicked(object? sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void OnAlertsClicked(object? sender, RoutedEventArgs e) =>
        AlertsPopup.IsOpen = !AlertsPopup.IsOpen;

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

    private static void SelectContainingListItem(Visual? visual)
    {
        while (visual is not null)
        {
            if (visual is ListBoxItem item && item.GetVisualParent() is ListBox list)
            {
                list.SelectedItem = item.DataContext;
                return;
            }

            visual = visual.GetVisualParent();
        }
    }
}
