// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Interop;
using Axiom.UI.ViewModels;

namespace Axiom.UI;

public partial class MainWindow : Window
{
    private const int WmGetMinMaxInfo = 0x0024;

    private const int MonitorDefaultToNearest = 2;

    private Point _titleBarDragStart;
    private bool _titleBarPressed;
    private bool _dragging;
    private HwndSource? _windowSource;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
    }

    private void OnTitleBarMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            _titleBarPressed = false;
            ToggleMaximize();
            e.Handled = true;
            return;
        }

        if (e.LeftButton == MouseButtonState.Pressed)
        {
            _titleBarPressed = true;
            _titleBarDragStart = e.GetPosition(this);
        }
    }

    private void OnTitleBarMouseMove(object sender, MouseEventArgs e)
    {
        if (!_titleBarPressed || _dragging || e.LeftButton != MouseButtonState.Pressed)
        {
            return;
        }

        var position = e.GetPosition(this);
        if (Math.Abs(position.X - _titleBarDragStart.X) < SystemParameters.MinimumHorizontalDragDistance &&
            Math.Abs(position.Y - _titleBarDragStart.Y) < SystemParameters.MinimumVerticalDragDistance)
        {
            return;
        }

        _dragging = true;
        _titleBarPressed = false;
        try
        {
            DragMove();
        }
        finally
        {
            _dragging = false;
        }
    }

    private void OnTitleBarMouseLeftButtonUp(object sender, MouseButtonEventArgs e) =>
        _titleBarPressed = false;

    private void OnMinimizeClicked(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximizeClicked(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void OnCloseClicked(object sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized
        ? WindowState.Normal
        : WindowState.Maximized;

    private void OnWindowStateChanged(object sender, EventArgs e)
    {
        if (MaximizeButton is null)
        {
            return;
        }

        var maximized = WindowState == WindowState.Maximized;
        MaximizeButton.Content = maximized ? "\uE923" : "\uE922";
        MaximizeButton.ToolTip = maximized ? "Restore" : "Maximize";
        AutomationProperties.SetName(MaximizeButton, maximized ? "Restore Axiom" : "Maximize Axiom");
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        _windowSource = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
        _windowSource?.AddHook(WindowProcedure);
    }

    private IntPtr WindowProcedure(
        IntPtr hwnd,
        int message,
        IntPtr wParam,
        IntPtr lParam,
        ref bool handled)
    {
        if (message == WmGetMinMaxInfo)
        {
            ApplyWorkAreaMaximizeBounds(hwnd, lParam);
            handled = true;
        }

        return IntPtr.Zero;
    }

    private static void ApplyWorkAreaMaximizeBounds(IntPtr hwnd, IntPtr minMaxInfoPointer)
    {
        var monitor = MonitorFromWindow(hwnd, MonitorDefaultToNearest);
        var monitorInfo = new MonitorInfo
        {
            Size = Marshal.SizeOf<MonitorInfo>(),
        };

        if (!GetMonitorInfo(monitor, ref monitorInfo))
        {
            return;
        }

        var work = monitorInfo.WorkArea;
        var screen = monitorInfo.MonitorArea;
        var info = Marshal.PtrToStructure<MinMaxInfo>(minMaxInfoPointer);

        // WindowChrome + WindowStyle=None otherwise maximizes over the taskbar on Windows 10.
        // Constrain both the maximize position and size to the monitor work area.
        info.MaxPosition = new NativePoint(work.Left - screen.Left, work.Top - screen.Top);
        info.MaxSize = new NativePoint(work.Right - work.Left, work.Bottom - work.Top);
        info.MaxTrackSize = new NativePoint(work.Right - work.Left, work.Bottom - work.Top);

        Marshal.StructureToPtr(info, minMaxInfoPointer, fDeleteOld: true);
    }

    protected override void OnClosed(EventArgs e)
    {
        _windowSource?.RemoveHook(WindowProcedure);
        _windowSource = null;
        (DataContext as IDisposable)?.Dispose();
        base.OnClosed(e);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;

        public int Y;

        public NativePoint(int x, int y)
        {
            X = x;
            Y = y;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;

        public int Top;

        public int Right;

        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MinMaxInfo
    {
        public NativePoint Reserved;

        public NativePoint MaxSize;

        public NativePoint MaxPosition;

        public NativePoint MinTrackSize;

        public NativePoint MaxTrackSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;

        public NativeRect MonitorArea;

        public NativeRect WorkArea;

        public uint Flags;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, int flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo monitorInfo);
}
