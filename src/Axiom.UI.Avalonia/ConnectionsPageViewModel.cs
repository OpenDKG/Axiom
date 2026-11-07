// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

public sealed partial class ConnectionsPageViewModel : PageViewModel, IDisposable
{
    private readonly ConnectionMonitor _monitor;

    public ConnectionsPageViewModel(ConnectionMonitor monitor)
        : base("Connections", "Sockets read from this Windows host · read-only", "C")
    {
        _monitor = monitor;
        _monitor.Updated += OnUpdated;
    }

    public ObservableCollection<ConnectionRow> Connections => _monitor.Connections;

    [ObservableProperty]
    private string _statusText = "Connecting to the socket inventory…";

    public void Dispose()
    {
        _monitor.Updated -= OnUpdated;
    }

    private void OnUpdated(object? sender, EventArgs e)
    {
        if (_monitor.LastError is { } error)
        {
            var captured = _monitor.LastCaptureUtc is { } timestamp
                ? $" · last capture {timestamp.ToLocalTime():HH:mm:ss}"
                : string.Empty;
            StatusText = $"Unavailable: {error}{captured}";
            return;
        }

        StatusText = $"Live read-only · {Connections.Count} sockets";
    }
}
