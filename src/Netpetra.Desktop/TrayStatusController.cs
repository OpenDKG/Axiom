// SPDX-License-Identifier: GPL-3.0-or-later
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Netpetra.UI;
using Netpetra.UI.Services;
using Netpetra.UI.ViewModels;

namespace Netpetra.Desktop;

/// <summary>
/// Shell notification-area status for measured NIC throughput and connection-monitor health.
/// No extra polling, upload or firewall mutation; data is taken from the existing UI engine.
/// </summary>
internal sealed class TrayStatusController : IDisposable
{
    private readonly MainWindow _window;
    private readonly MainViewModel _viewModel;
    private readonly ConnectionMonitor _monitor;
    private readonly NotifyIcon _tray;
    private readonly ContextMenuStrip _menu;
    private readonly ToolStripMenuItem _ratesItem;
    private readonly ToolStripMenuItem _healthItem;
    private readonly ToolStripMenuItem _notificationsItem;
    private readonly Icon _healthyIcon;
    private readonly Icon _problemIcon;
    private bool _issueActive;
    private bool _disposed;

    public TrayStatusController(MainWindow window, MainViewModel viewModel, ConnectionMonitor monitor)
    {
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));

        _healthyIcon = CreateStatusIcon(false);
        _problemIcon = CreateStatusIcon(true);

        _menu = new ContextMenuStrip();
        _ratesItem = new ToolStripMenuItem("↑ —   ↓ —") { Enabled = false };
        _healthItem = new ToolStripMenuItem("Monitoring: initializing") { Enabled = false };
        _notificationsItem = new ToolStripMenuItem("Show problem notifications")
        {
            CheckOnClick = true,
            Checked = TraySettingsStore.Enabled,
        };
        _notificationsItem.CheckedChanged += OnNotificationsCheckedChanged;

        var openItem = new ToolStripMenuItem("Open Netpetra");
        openItem.Click += OnOpenClicked;
        var exitItem = new ToolStripMenuItem("Exit Netpetra");
        exitItem.Click += OnExitClicked;

        _menu.Items.Add(_ratesItem);
        _menu.Items.Add(_healthItem);
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add(openItem);
        _menu.Items.Add(_notificationsItem);
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add(exitItem);

        _tray = new NotifyIcon
        {
            Icon = _healthyIcon,
            Text = "Netpetra | waiting for measured rates",
            ContextMenuStrip = _menu,
            Visible = true,
        };
        _tray.DoubleClick += OnTrayDoubleClicked;
        _tray.MouseClick += OnTrayMouseClicked;

        _viewModel.TrayStatusUpdated += OnStatusUpdated;
        TraySettingsStore.Changed += OnTraySettingsChanged;
        Update();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _viewModel.TrayStatusUpdated -= OnStatusUpdated;
        TraySettingsStore.Changed -= OnTraySettingsChanged;
        _tray.DoubleClick -= OnTrayDoubleClicked;
        _tray.MouseClick -= OnTrayMouseClicked;
        _notificationsItem.CheckedChanged -= OnNotificationsCheckedChanged;

        _tray.Visible = false;
        _tray.Dispose();
        _menu.Dispose();
        _healthyIcon.Dispose();
        _problemIcon.Dispose();
    }

    private void OnStatusUpdated(object? sender, EventArgs e) => Update();

    private void OnTraySettingsChanged(object? sender, EventArgs e) =>
        _notificationsItem.Checked = TraySettingsStore.Enabled;

    private void OnNotificationsCheckedChanged(object? sender, EventArgs e) =>
        TraySettingsStore.SetEnabled(_notificationsItem.Checked);

    private void OnOpenClicked(object? sender, EventArgs e) => ShowWindow();

    private void OnExitClicked(object? sender, EventArgs e) => _window.Close();

    private void OnTrayDoubleClicked(object? sender, EventArgs e) => ShowWindow();

    private void OnTrayMouseClicked(object? sender, MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            ShowWindow();
        }
    }

    public void ShowWindow()
    {
        if (!_window.IsVisible)
        {
            _window.Show();
        }

        if (_window.WindowState == System.Windows.WindowState.Minimized)
        {
            _window.WindowState = System.Windows.WindowState.Normal;
        }

        _window.Activate();
    }

    private void Update()
    {
        if (_disposed)
        {
            return;
        }

        var upload = ByteFormatter.Rate(_viewModel.CurrentUploadBytesPerSecond);
        var download = ByteFormatter.Rate(_viewModel.CurrentDownloadBytesPerSecond);
        var issue = CurrentMonitoringIssue();
        var isProblem = issue is not null;

        _tray.Icon = isProblem ? _problemIcon : _healthyIcon;

        _ratesItem.Text = $"↑ {upload}  |  ↓ {download}";
        _healthItem.Text = isProblem ? "Monitoring: problem (open app for details)" : "Monitoring: operating";
        _tray.Text = isProblem
            ? "Netpetra ! Monitoring problem | open app"
            : Shorten($"Netpetra ↑ {upload} ↓ {download}", 63);

        // Notify on a transition into a known monitoring failure, never on every poll.
        if (isProblem && !_issueActive && TraySettingsStore.Enabled)
        {
            _tray.ShowBalloonTip(
                5000,
                "Netpetra: network monitoring problem",
                Shorten(issue!, 180),
                ToolTipIcon.Warning);
        }

        _issueActive = isProblem;
    }

    private string? CurrentMonitoringIssue()
    {
        if (!string.IsNullOrWhiteSpace(_monitor.LastError))
        {
            return $"Network monitoring failed: {_monitor.LastError}";
        }

        if (_monitor.IsRunning && _monitor.LastCaptureUtc is { } captured)
        {
            var allowedAge = TimeSpan.FromSeconds(
                Math.Max(10, _monitor.PollInterval.TotalSeconds * 5));

            if (DateTimeOffset.UtcNow - captured > allowedAge)
            {
                return $"Network connection snapshot stale since {captured.ToLocalTime():HH:mm:ss}.";
            }
        }

        return null;
    }

    private static string Shorten(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..(maxLength - 1)] + "…";

    private static Icon CreateStatusIcon(bool problem)
    {
        using var bitmap = new Bitmap(32, 32);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.Clear(Color.Transparent);

        using var background = new SolidBrush(Color.FromArgb(17, 29, 45));
        using var teal = new Pen(Color.FromArgb(90, 231, 207), 3.1f);
        using var blue = new Pen(Color.FromArgb(115, 170, 255), 3.1f);
        graphics.FillEllipse(background, 1, 1, 30, 30);

        // Two directional traces are intentionally distinct from any third-party logo.
        graphics.DrawLine(teal, 9, 21, 9, 8);
        graphics.DrawLine(teal, 5, 12, 9, 8);
        graphics.DrawLine(teal, 13, 12, 9, 8);
        graphics.DrawLine(blue, 21, 9, 21, 22);
        graphics.DrawLine(blue, 17, 18, 21, 22);
        graphics.DrawLine(blue, 25, 18, 21, 22);

        if (problem)
        {
            using var red = new SolidBrush(Color.FromArgb(229, 53, 61));
            using var white = new SolidBrush(Color.White);
            using var font = new Font("Segoe UI", 13, FontStyle.Bold, GraphicsUnit.Pixel);
            graphics.FillEllipse(red, 18, 17, 13, 13);
            graphics.DrawString("!", font, white, 21, 16);
        }

        var handle = bitmap.GetHicon();
        try
        {
            using var temporary = Icon.FromHandle(handle);
            return (Icon)temporary.Clone();
        }
        finally
        {
            NativeMethods.DestroyIcon(handle);
        }
    }

    private static class NativeMethods
    {
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DestroyIcon(nint handle);
    }
}
