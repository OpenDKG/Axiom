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

    /// <summary>
    /// The XAML size is the preferred desktop size. On a smaller display the window must still open
    /// fully inside the screen working area at the active DPI scale, not at negative coordinates.
    /// </summary>
    private void FitToWorkingArea()
    {
        try
        {
            // The platform screen list exists only once the window is opened (X11/Windows).
            var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary;
            if (screen is null)
            {
                return;
            }

            var (width, height, position) = FitToWorkingArea(
                Width, Height, MinWidth, MinHeight, screen.WorkingArea, screen.Scaling);
            // A work area smaller than the 900x600 minimum cannot honour that minimum; lower the
            // floor only as far as the screen requires so the window still opens fully visible.
            MinWidth = Math.Min(MinWidth, width);
            MinHeight = Math.Min(MinHeight, height);
            Width = width;
            Height = height;
            WindowStartupLocation = WindowStartupLocation.Manual;
            Position = position;
        }
        catch (InvalidOperationException)
        {
            // No platform screen yet (headless/early startup); keep the centered XAML default.
        }
    }

    internal static (double Width, double Height, PixelPoint Position) FitToWorkingArea(
        double width,
        double height,
        double minWidth,
        double minHeight,
        PixelRect workingArea,
        double scaling)
    {
        if (!double.IsFinite(scaling) || scaling <= 0)
        {
            scaling = 1;
        }

        var availableWidth = workingArea.Width / scaling;
        var availableHeight = workingArea.Height / scaling;
        var fittedWidth = Math.Max(
            Math.Min(width, availableWidth),
            Math.Min(minWidth, availableWidth));
        var fittedHeight = Math.Max(
            Math.Min(height, availableHeight),
            Math.Min(minHeight, availableHeight));
        // Ceiling can overshoot by one pixel at fractional scales (1280/1.5 -> 1280.0000000000002).
        // Cap in pixels first, then report the DIP size that maps back to that pixel count.
        var pixelWidth = Math.Min((int)Math.Ceiling(fittedWidth * scaling), workingArea.Width);
        var pixelHeight = Math.Min((int)Math.Ceiling(fittedHeight * scaling), workingArea.Height);
        fittedWidth = pixelWidth / scaling;
        fittedHeight = pixelHeight / scaling;

        return (
            fittedWidth,
            fittedHeight,
            new PixelPoint(
                workingArea.X + Math.Max(0, (workingArea.Width - pixelWidth) / 2),
                workingArea.Y + Math.Max(0, (workingArea.Height - pixelHeight) / 2)));
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        FitToWorkingArea();

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
