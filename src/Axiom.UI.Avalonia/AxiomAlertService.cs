// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Small always-on-top notification card shown near the clock. It is used only while the main
/// window is minimized, hidden in the tray or inactive; the opt-out is the notification setting,
/// separate from the visible tray icon.
/// </summary>
public static class AxiomAlertService
{
    private static IBrush Surface => AxiomDialogTheme.Surface;
    private static IBrush WindowBackground => AxiomDialogTheme.WindowBackground;
    private static IBrush Border => AxiomDialogTheme.Border;
    private static IBrush Primary => AxiomDialogTheme.TextPrimary;
    private static IBrush Muted => AxiomDialogTheme.TextMuted;
    private static IBrush Critical => AxiomDialogTheme.Critical;
    private static readonly Queue<AlertRequest> Pending = new();
    private static Func<Window?>? _windowProvider;
    private static Action? _showWindow;
    private static Action<Type, IReadOnlyList<string>>? _navigate;
    private static Window? _current;

    public static void Configure(
        Func<Window?> windowProvider,
        Action showWindow,
        Action<Type, IReadOnlyList<string>>? navigate = null)
    {
        _windowProvider = windowProvider ?? throw new ArgumentNullException(nameof(windowProvider));
        _showWindow = showWindow ?? throw new ArgumentNullException(nameof(showWindow));
        _navigate = navigate;
    }

    public static void Show(
        string title,
        string message,
        Action? onOpen = null,
        bool force = false,
        Type? page = null,
        IReadOnlyList<string>? focusApps = null,
        TimeSpan? lifetime = null)
    {
        if (!Dispatcher.UIThread.CheckAccess())
        {
            Dispatcher.UIThread.Post(() => Show(title, message, onOpen, force, page, focusApps, lifetime));
            return;
        }

        // Keep every alert in the in-app history, even when the toast itself is suppressed
        // because the window is active or tray notifications are disabled.
        AlertCenter.Record(title, message, page, focusApps);

        if (!force && !NotificationSettingsStore.Enabled)
        {
            return;
        }

        if (!force && !ShouldNotify())
        {
            return;
        }

        Pending.Enqueue(new AlertRequest(
            title,
            message,
            onOpen,
            force,
            page,
            focusApps ?? [],
            lifetime ?? TimeSpan.FromSeconds(12)));
        ShowNext();
    }

    private static bool ShouldNotify()
    {
        if (!NotificationSettingsStore.Enabled)
        {
            return false;
        }

        var window = _windowProvider?.Invoke();
        if (window is null)
        {
            return false;
        }

        return !window.IsVisible ||
               window.WindowState == WindowState.Minimized ||
               !window.IsActive;
    }

    private static void ShowNext()
    {
        if (_current is not null || Pending.Count == 0)
        {
            return;
        }

        if (!Pending.Peek().Force && !ShouldNotify())
        {
            Pending.Clear();
            return;
        }

        var request = Pending.Dequeue();
        var toast = BuildWindow(request);
        _current = toast;
        toast.Closed += (_, _) =>
        {
            _current = null;
            Dispatcher.UIThread.Post(ShowNext);
        };
        toast.Show();
    }

    private static Window BuildWindow(AlertRequest request)
    {
        var toast = new Window
        {
            Width = 380,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            ShowInTaskbar = false,
            ShowActivated = false,
            Topmost = true,
            WindowStartupLocation = WindowStartupLocation.Manual,
            WindowDecorations = WindowDecorations.None,
            Background = WindowBackground,
        };

        var icon = new Image
        {
            Source = new Bitmap(AssetLoader.Open(
                new Uri("avares://Axiom.UI.Avalonia/Assets/axiom-icon.png"))),
            Width = 22,
            Height = 22,
            Stretch = Stretch.Uniform,
            VerticalAlignment = VerticalAlignment.Center,
        };

        var heading = new TextBlock
        {
            Text = "AXIOM",
            Foreground = Critical,
            FontSize = 10,
            FontWeight = FontWeight.Bold,
            VerticalAlignment = VerticalAlignment.Center,
        };

        var title = new TextBlock
        {
            Text = request.Title,
            Foreground = Primary,
            FontSize = 13,
            FontWeight = FontWeight.SemiBold,
            TextWrapping = TextWrapping.Wrap,
        };

        var message = new TextBlock
        {
            Text = request.Message,
            Foreground = Muted,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
        };

        var open = new Button
        {
            Content = AlertRecord.ActionTextFor(request.Page),
            Padding = new Thickness(12, 6),
            Background = AxiomDialogTheme.Accent,
            Foreground = AxiomDialogTheme.AccentContrast,
            BorderBrush = AxiomDialogTheme.Accent,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Classes = { "primary" },
        };

        var close = new Button
        {
            Content = "\u00D7",
            Width = 30,
            Height = 28,
            Padding = new Thickness(0),
            HorizontalContentAlignment = HorizontalAlignment.Center,
            VerticalContentAlignment = VerticalAlignment.Center,
            Background = AxiomDialogTheme.SurfaceAlt,
            Foreground = Primary,
            BorderBrush = Border,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
        };

        var header = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            Children = { icon, heading },
        };

        var actions = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            HorizontalAlignment = HorizontalAlignment.Right,
            Children = { open, close },
        };

        var content = new StackPanel { Spacing = 8, Children = { header, title, message, actions } };
        var card = new Border
        {
            Background = Surface,
            BorderBrush = Border,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(14),
            Child = content,
        };

        toast.Content = card;
        toast.Opened += (_, _) => Dispatcher.UIThread.Post(
            () => Position(toast),
            DispatcherPriority.Background);
        open.Click += (_, _) =>
        {
            toast.Close();
            if (request.OnOpen is not null)
            {
                request.OnOpen();
                return;
            }

            // Bring the shell back first, then select the page the alert belongs to.
            _showWindow?.Invoke();
            if (request.Page is not null)
            {
                _navigate?.Invoke(request.Page, request.FocusApps);
            }
        };
        close.Click += (_, _) => toast.Close();

        var timer = new DispatcherTimer { Interval = request.Lifetime };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            toast.Close();
        };
        timer.Start();
        toast.PointerEntered += (_, _) => timer.Stop();
        toast.PointerExited += (_, _) => timer.Start();
        toast.Closed += (_, _) => timer.Stop();
        return toast;
    }

    private static void Position(Window toast)
    {
        try
        {
            var screen = toast.Screens.Primary;
            if (screen is null)
            {
                return;
            }

            var scaling = toast.RenderScaling <= 0 ? 1 : toast.RenderScaling;
            var width = (int)Math.Ceiling(380 * scaling);
            var height = (int)Math.Ceiling(
                (toast.Bounds.Height > 20 ? toast.Bounds.Height : 150) * scaling);
            var area = screen.WorkingArea;
            toast.Position = new PixelPoint(
                Math.Max(area.X, area.Right - width - 16),
                Math.Max(area.Y, area.Bottom - height - 16));
        }
        catch (InvalidOperationException)
        {
        }
    }

    private sealed record AlertRequest(
        string Title,
        string Message,
        Action? OnOpen,
        bool Force,
        Type? Page,
        IReadOnlyList<string> FocusApps,
        TimeSpan Lifetime);
}
